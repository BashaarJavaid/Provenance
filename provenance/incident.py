"""The incident control loop (item 9) — the graph, and everything the graph is not allowed
to delegate to a model.

`docs/adr/ADR-007` commits the fleet to ADK's Graph Runtime for exactly one reason: "bounded
retry is a property of the *routing graph*, not of any agent's prompt (§7.1). A declarative
graph makes the retry budget and escalation edges visible and testable -- no agent owns its
own iteration count." So the loop is a `Workflow`, and §7.1's one re-plan is a real edge from
the validation node back to the Planner, not a `while` loop hidden in a prompt.

    START -> orchestrator -> recall -> route ?-> sre_infra -> planner -> validate ?-> authorize
                                            `-> halt (UNROUTABLE)                 |-> planner (REPLAN)
                                                                                  `-> halt (ESCALATE)

Three properties this file is responsible for, and no other file is:

1. **The malformed count.** §7.1: "no agent owns its own iteration count -- the control loop
   does, in code." `action.outcome_for()` shipped in item 6 with no caller for exactly this.
2. **The root span.** Item 2 shipped four span shapes and recorded that the incident root
   "arrives with the Orchestrator in item 9". Everything else nests under it.
3. **Nothing reaches a state-mutating action except through the gateway** (§1.1 property 1).
   The authorize node calls `gateway.authorize()` and there is no second path; a diagnosis
   that never becomes a validated Action simply ends the incident.

Item 9 stops at the signed decision. Nothing executes and nothing is verified -- that is item
10, which appends nodes rather than reshaping these.

Agents and the graph are built per incident. Two runs must not share the per-invocation
tracing state in `_reasoning.py`, and a test must be able to substitute a fake model without
mutating a module global.
"""

from __future__ import annotations

import os
import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from google.adk.agents.context import Context
from google.adk.runners import Runner
from google.adk.sessions import InMemorySessionService
from google.adk.workflow import START, Workflow
from google.genai import types

from provenance import action, credentials, gateway, models, registry, telemetry, tools
from provenance.agents import _reasoning, orchestrator, planner, sre_infra
from provenance.synthetic import company
from provenance.telemetry import IncidentOutcome, TriggerSignal

# The one place a domain becomes routable: name -> (agent id, what the domain covers).
# Item 21 adds one entry and one agent file and changes nothing else here, which is what
# item 22 measures. The scope travels with the mapping because the Orchestrator's vocabulary
# and the routing table have to be the same list: a domain it can name but not reach, or
# reach but not name, is a silently unroutable incident.
DOMAINS: dict[str, tuple[str, str]] = {
    sre_infra.DOMAIN: ("sre-infra-agent", sre_infra.DOMAIN_SCOPE),
}

PLANNER_ID = "remediation-planner"

# The Orchestrator holds no authority: it proposes no action and writes no belief, so §3.4
# has nothing to record about it. Its span's `agent.id` says who reasoned, which is a
# different question from who may act.
ORCHESTRATOR_ID = "orchestrator"
ORCHESTRATOR_VERSION = "v1"

PLANNER_KEY_ENV = "PROVENANCE_PLANNER_KEY"

_APP = "provenance"


@dataclass(frozen=True)
class Trigger:
    """One wake-on-event from the trigger stream (§5.3).

    Deliberately not a fifth §3 object. §3's four shapes "carry all authority-relevant data";
    a trigger carries none -- it is an observation that starts reasoning, and every field on
    it is re-derived from an authority before anything is decided. It is not persisted for
    the same reason: nothing reads an incident's trigger after the incident.
    """

    target: str
    signal: TriggerSignal
    observed_value: float
    observed_at: str


@dataclass(frozen=True)
class IncidentResult:
    """What one turn of the loop produced. `outcome` is the discriminator, not `decision`."""

    incident_id: str
    outcome: IncidentOutcome
    decision: gateway.Decision | None
    action: action.Action | None
    malformed_attempts: int


@dataclass
class _Scratch:
    """What the graph's nodes produce, kept out of session state.

    Session state holds only what an agent's instruction interpolates -- strings and numbers
    that survive being written to a session store. A `Decision` and an `Action` are neither,
    and round-tripping them through JSON would mean the object the caller inspects is not the
    object the gateway signed.
    """

    outcome: IncidentOutcome = "ESCALATED"
    decision: gateway.Decision | None = None
    validated: action.Action | None = None
    proposal: dict[str, Any] | None = None
    malformed_attempts: int = 0
    reasons: list[str] = field(default_factory=list)


def load_planner_key() -> ec.EllipticCurvePrivateKey:
    """The Planner's private half, from the environment.

    ponytail: an env var, not Secret Manager. `seed_registry.py` prints each private half
    once and stores it nowhere (ADR-010), so something outside the repo has to carry it, and
    item 7 already took this posture for the gateway's own signing key. Upgrade path is
    Secret Manager with the runtime service account granted accessor; the shape of this
    function does not change when it happens.
    """
    pem = os.environ.get(PLANNER_KEY_ENV)
    if not pem:
        raise RuntimeError(f"{PLANNER_KEY_ENV} is not set; the Planner cannot sign a credential")
    key = serialization.load_pem_private_key(pem.encode(), password=None)
    if not isinstance(key, ec.EllipticCurvePrivateKey):
        raise TypeError(f"{PLANNER_KEY_ENV} is not an EC private key")
    return key


async def recall(entity_id: str) -> tuple[str, ...]:
    """What memory already believes about this entity (§6.6).

    Empty until item 16 builds recall against the item-12 belief store. The step exists now
    so that item 18's `verify:` line -- "the recall event appears in the trace before the
    domain agent's first hypothesis" -- has a slot to fill rather than a graph to reshape,
    and so the reasoning spans carry `recall.belief_ids` from the first incident onward.
    """
    return ()


def _seed_state(
    trigger: Trigger, planner_version: str, recalled: tuple[str, ...]
) -> dict[str, Any]:
    """Everything an agent instruction interpolates. Facts come from authorities, not the trigger.

    The trigger reports what was observed; the tier, the config versions and the description
    are read from the entity model, which is the same authority `action.validate()` checks the
    Planner's declared tier against. A trigger that lied about a tier would change no prompt.
    """
    service = company.service(trigger.target)
    return {
        "trigger_target": trigger.target,
        "trigger_signal": trigger.signal,
        "trigger_observed_value": trigger.observed_value,
        "trigger_observed_at": trigger.observed_at,
        "target_tier": service.tier,
        "target_description": service.description,
        "current_config_version": service.current_config_version or "unknown",
        "known_good_version": service.known_good_version or "unknown",
        "known_action_classes": ", ".join(tool.action_class for tool in tools.TOOLS),
        "planner_identity": f"{PLANNER_ID}@{planner_version}",
        "recall_summary": "none" if not recalled else ", ".join(recalled),
        _reasoning.RECALL_BELIEF_IDS: list(recalled),
        "malformed_feedback": "",
        "diagnosis_summary": "",
    }


def build_graph(
    *,
    scratch: _Scratch,
    planner_version: str,
    planner_key: ec.EllipticCurvePrivateKey,
    now: datetime,
    client: Any | None,
    model_orchestrator: str | object,
    model_domain: str | object,
    model_planner: str | object,
) -> Workflow:
    """The §2.1 + §7.1 routing graph. Every node but the three agents is deterministic code."""
    orchestrator_agent = orchestrator.build(
        model_orchestrator,
        agent_id=ORCHESTRATOR_ID,
        agent_version=ORCHESTRATOR_VERSION,
        domains=tuple((name, scope) for name, (_, scope) in DOMAINS.items()),
    )
    domain_agent = sre_infra.build(
        model_domain, agent_id=DOMAINS[sre_infra.DOMAIN][0], agent_version="v1"
    )
    planner_agent = planner.build(model_planner, agent_id=PLANNER_ID, agent_version=planner_version)

    def route(ctx: Context, classification: dict[str, Any]) -> None:
        """Registry lookup, not judgement. An unclassifiable incident ends here, visibly."""
        domain = str(classification.get("domain", ""))
        entry = DOMAINS.get(domain)
        if entry is None:
            scratch.outcome = "UNROUTABLE"
            scratch.reasons.append(f"no agent registered for domain {domain!r}")
            ctx.route = "UNROUTABLE"
            return
        ctx.state["routed_domain"] = domain
        ctx.state["routed_to"] = entry[0]
        ctx.route = "ROUTED"

    def hand_off(ctx: Context, diagnosis: dict[str, Any]) -> None:
        """Give the Planner the diagnosis as text. §2.1 keeps diagnosing and proposing apart."""
        ctx.state["diagnosis_summary"] = (
            f"{diagnosis.get('selected_hypothesis', '')}: {diagnosis.get('summary', '')} "
            f"(evidence: {', '.join(str(ref) for ref in diagnosis.get('evidence_refs', []))}; "
            f"recommended action class: {diagnosis.get('recommended_action_class', 'NONE')})"
        )

    def validate(ctx: Context, proposal: dict[str, Any]) -> None:
        """§7.1's schema gate and the retry budget the control loop owns.

        A malformed emission dies here, before the gateway sees it, and is returned to the
        Planner exactly once. The count lives on `scratch`, never on the agent.
        """
        candidate = planner.to_proposal(proposal)
        try:
            scratch.validated = action.validate(candidate)
        except action.ActionError as error:
            scratch.malformed_attempts += 1
            scratch.reasons.append(f"{type(error).__name__}: {error}")
            if action.outcome_for(scratch.malformed_attempts) == "REJECT":
                ctx.state["malformed_feedback"] = (
                    "Your previous emission was rejected before authorization. Fix exactly "
                    f"this and emit one action again: {error}"
                )
                ctx.route = "REPLAN"
                return
            scratch.outcome = "ESCALATED"
            ctx.route = "ESCALATE"
            return
        scratch.proposal = candidate
        ctx.route = "AUTHORIZE"

    async def authorize(ctx: Context) -> None:
        """§1.1 property 1: the only path from reasoning to a state-mutating action."""
        assert scratch.proposal is not None  # `validate` routes here only on success
        credential = credentials.mint(PLANNER_ID, planner_version, planner_key, now=now)
        # The gateway takes `object` and runs schema validation itself (item 7). Handing it
        # the same dict rather than the validated Action is what keeps that true: there is no
        # shortcut into the pipeline that skips a stage.
        decision = await gateway.authorize(scratch.proposal, credential, now=now, client=client)
        scratch.decision = decision
        scratch.outcome = _OUTCOME_FOR[decision.outcome]

    def halt() -> None:
        """The terminal node for the two branches that never reach the gateway."""

    return Workflow(
        name="incident",
        edges=[
            (START, orchestrator_agent),
            (orchestrator_agent, route),
            (route, {"ROUTED": domain_agent, "UNROUTABLE": halt}),
            (domain_agent, hand_off),
            (hand_off, planner_agent),
            (planner_agent, validate),
            (validate, {"AUTHORIZE": authorize, "REPLAN": planner_agent, "ESCALATE": halt}),
        ],
    )


# The gateway's four outcomes, as the incident-level facts §8.1 records. A held incident is
# not a failed one: it is waiting on the human §2.1 stage 7 put there.
_OUTCOME_FOR: dict[telemetry.AuthOutcome, IncidentOutcome] = {
    "APPROVE": "AUTHORIZED",
    "APPROVE_NOTIFY": "AUTHORIZED",
    "HOLD": "HELD",
    "DENY": "DENIED",
}


async def run_incident(
    trigger: Trigger,
    *,
    now: datetime | None = None,
    client: Any | None = None,
    planner_key: ec.EllipticCurvePrivateKey | None = None,
    model_orchestrator: str | object = None,
    model_domain: str | object = None,
    model_planner: str | object = None,
) -> IncidentResult:
    """One trigger, one incident, one root span. Never raises on a bad proposal.

    The model arguments exist so tests can substitute a fake `BaseLlm`; unset, each falls
    back to its `models.py` role string. Everything else the loop needs -- the Planner's
    version and public key -- is read from the registry at request time (§1.1 property 4),
    never from a constant here.
    """
    now = now or datetime.now(UTC)
    incident_id = f"inc-{uuid.uuid4().hex[:12]}"
    scratch = _Scratch()

    with telemetry.incident(
        incident_id=incident_id,
        trigger_target=trigger.target,
        trigger_signal=trigger.signal,
    ) as recorder:
        agent = await registry.get_agent(PLANNER_ID, client=client)
        recalled = await recall(trigger.target)
        state = _seed_state(trigger, agent.version, recalled)

        graph = build_graph(
            scratch=scratch,
            planner_version=agent.version,
            planner_key=planner_key or load_planner_key(),
            now=now,
            client=client,
            model_orchestrator=model_orchestrator or models.ORCHESTRATOR,
            model_domain=model_domain or models.DOMAIN,
            model_planner=model_planner or models.PLANNER,
        )

        sessions = InMemorySessionService()
        await sessions.create_session(
            app_name=_APP, user_id=incident_id, session_id=incident_id, state=state
        )
        runner = Runner(node=graph, app_name=_APP, session_service=sessions)
        async for _ in runner.run_async(
            user_id=incident_id,
            session_id=incident_id,
            new_message=types.Content(role="user", parts=[types.Part(text=trigger.signal)]),
        ):
            pass

        session = await sessions.get_session(
            app_name=_APP, user_id=incident_id, session_id=incident_id
        )
        if session is not None and session.state.get("routed_to"):
            recorder.set_routing(
                domain=str(session.state["routed_domain"]),
                routed_to=str(session.state["routed_to"]),
            )
        recorder.set_outcome(
            outcome=scratch.outcome,
            malformed_attempts=scratch.malformed_attempts,
            predicate_id=(
                None if scratch.validated is None else action.predicate_id(scratch.validated)
            ),
        )

    return IncidentResult(
        incident_id=incident_id,
        outcome=scratch.outcome,
        decision=scratch.decision,
        action=scratch.validated,
        malformed_attempts=scratch.malformed_attempts,
    )
