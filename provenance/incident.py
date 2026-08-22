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

    authorize ?-> execute ?-> verification -> resolve      (item 10)
              |           `-> halt (execution failed)
              `-> halt (HELD | DENIED)

Four properties this file is responsible for, and no other file is:

1. **The malformed count.** §7.1: "no agent owns its own iteration count -- the control loop
   does, in code." `action.outcome_for()` shipped in item 6 with no caller for exactly this.
2. **The root span.** Item 2 shipped four span shapes and recorded that the incident root
   "arrives with the Orchestrator in item 9". Everything else nests under it.
3. **Nothing reaches a state-mutating action except through the gateway** (§1.1 property 1).
   The authorize node calls `gateway.authorize()` and there is no second path; a diagnosis
   that never becomes a validated Action simply ends the incident. Since item 10 something
   downstream actually mutates state, and `executor.execute()` re-checks the decision's
   signature, outcome and subject rather than trusting that this node routed correctly.
4. **§7.2's rule for learning.** A belief is committed on `CONFIRMED` and on nothing else.
   `REFUTED` and `INCONCLUSIVE` both escalate and write nothing -- no partial credit.

Item 10 appended `execute`, the Verification Agent and `resolve`, and gave `authorize` a
`ctx.route`; nothing else about the item-9 graph changed. `resolve` is the node that opens
the `verification.outcome` span, because `belief_written` is not known until the commit has
been attempted -- so the `belief.commit` span nests inside it.

Agents and the graph are built per incident. Two runs must not share the per-invocation
tracing state in `_reasoning.py`, and a test must be able to substitute a fake model without
mutating a module global.
"""

from __future__ import annotations

import os
import uuid
from collections.abc import Mapping
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from typing import Any, get_args

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from google.adk.agents.context import Context
from google.adk.runners import Runner
from google.adk.sessions import InMemorySessionService
from google.adk.workflow import START, Workflow
from google.genai import types

from provenance import (
    action,
    beliefs,
    credentials,
    executor,
    gateway,
    models,
    policy,
    registry,
    telemetry,
    tools,
)
from provenance.agents import _reasoning, orchestrator, planner, sre_infra, verification
from provenance.synthetic import company
from provenance.telemetry import IncidentOutcome, TriggerSignal, VerificationOutcome

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

# The Verification Agent holds no registry record, for the Orchestrator's reason (§3.4): it
# proposes no action and writes no belief.
VERIFICATION_ID = "verification-agent"
VERIFICATION_VERSION = "v1"

# The domain-typed status a confirmed rollback teaches (§3.2: "domain-typed; UNKNOWN and
# RETRACTED are universal"). A constant while the stub Policy Engine is the only writer --
# item 14's Memory Analyst is what proposes a status, and this line is what it replaces.
BELIEF_STATUS = "CONFIG_REGRESSION_PRONE"

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
    """What one turn of the loop produced. `outcome` is the discriminator, not `decision`.

    The last three are `None` whenever the path was not taken -- a held incident executes
    nothing, an escalated one verifies nothing, and an INCONCLUSIVE verification writes no
    belief. Absent means the stage did not happen, never that it happened emptily.
    """

    incident_id: str
    outcome: IncidentOutcome
    decision: gateway.Decision | None
    action: action.Action | None
    malformed_attempts: int
    execution: executor.ExecutionResult | None = None
    verification: VerificationOutcome | None = None
    belief: policy.BeliefCommit | None = None


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
    execution: executor.ExecutionResult | None = None
    post_state: executor.ServiceState | None = None
    verification: VerificationOutcome | None = None
    belief: policy.BeliefCommit | None = None


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
        # Item 11.5. What healthy looks like, from the frozen fixture and never from the
        # trigger: `executor.execute()` writes this exact value back on a successful rollback,
        # so a Planner told the *spiked* rate would declare a threshold no success can satisfy.
        # Both units because the defect was a units collision -- the model translated 0.01 into
        # "less than 1%" and could not see it had landed on the baseline.
        "nominal_error_rate": service.error_rate,
        "nominal_error_rate_pct": f"{service.error_rate * 100:g}",
        "known_action_classes": ", ".join(tool.action_class for tool in tools.TOOLS),
        "planner_identity": f"{PLANNER_ID}@{planner_version}",
        "recall_summary": "none" if not recalled else ", ".join(recalled),
        _reasoning.RECALL_BELIEF_IDS: list(recalled),
        "malformed_feedback": "",
        "diagnosis_summary": "",
        # Item 10. The Verification Agent's instruction interpolates all three, and the
        # `execute` node overwrites them with what it measured; seeded here because an
        # instruction naming a key that was never seeded fails at interpolation time.
        "success_predicate": "",
        "post_error_rate": trigger.observed_value,
        "post_config_version": service.current_config_version or "unknown",
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
    model_verification: str | object,
) -> Workflow:
    """The §2.1 + §7.1 routing graph. Every node but the four agents is deterministic code."""
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
    verification_agent = verification.build(
        model_verification, agent_id=VERIFICATION_ID, agent_version=VERIFICATION_VERSION
    )

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
        # A HOLD parks on a human (§2.1 stage 7, item 30) and a DENY is over. Only an
        # approval continues, and `executor.execute()` re-checks the signature anyway.
        ctx.route = "EXECUTE" if decision.outcome in executor.APPROVING else "HALT"

    async def execute(ctx: Context) -> None:
        """The one node that changes the world. Nothing here decides whether it may."""
        assert scratch.validated is not None and scratch.decision is not None
        try:
            scratch.execution = await executor.execute(
                scratch.validated, scratch.decision, client=client
            )
            scratch.post_state = await executor.read_state(scratch.validated.target, client=client)
        except executor.ExecutionError as error:
            # §7.3's default posture, made a row in that table: an execution that did not
            # happen verifies nothing and teaches nothing.
            scratch.outcome = "ESCALATED"
            scratch.reasons.append(f"{type(error).__name__}: {error}")
            ctx.route = "HALT"
            return
        ctx.state["success_predicate"] = scratch.validated.success_predicate
        ctx.state["post_error_rate"] = scratch.post_state.error_rate
        ctx.state["post_config_version"] = scratch.post_state.config_version
        ctx.route = "VERIFY"

    async def resolve(ctx: Context, verification: dict[str, Any]) -> None:
        """§7.2's table: what was learned, and whether the incident is over.

        The parameter name is load-bearing: ADK resolves a node's arguments out of session
        state by name, so this must be the agent's `output_key`. Same rule as `hand_off`'s
        `diagnosis` and `validate`'s `proposal`. It shadows the module of the same name,
        which is why `verification_agent` is bound above rather than built here.
        """
        await _resolve(
            scratch,
            verification,
            model=_reasoning.model_name(verification_agent),
            domain=str(ctx.state.get("routed_domain", "")),
            agent_id=str(ctx.state.get("routed_to", "")),
            now=now,
            client=client,
        )

    def halt() -> None:
        """The terminal node for every branch that stops before the fleet has learned."""

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
            (authorize, {"EXECUTE": execute, "HALT": halt}),
            (execute, {"VERIFY": verification_agent, "HALT": halt}),
            (verification_agent, resolve),
        ],
    )


def _verification_outcome(verified: object) -> VerificationOutcome:
    """The agent's own enum, or INCONCLUSIVE.

    §7.3 treats a verification agent that errors or times out as INCONCLUSIVE, and an answer
    that cannot be read is the same thing: escalate, learn nothing. There is no reading of a
    missing answer that could justify writing a belief.
    """
    outcome = verified.get("outcome") if isinstance(verified, Mapping) else None
    return outcome if outcome in get_args(VerificationOutcome) else "INCONCLUSIVE"  # type: ignore[return-value]


async def _resolve(
    scratch: _Scratch,
    verified: object,
    *,
    model: str,
    domain: str,
    agent_id: str,
    now: datetime,
    client: Any | None,
) -> None:
    """Open `verification.outcome`, apply §7.2's table, and record what came of it.

    | outcome | belief | incident |
    |---|---|---|
    | `CONFIRMED` | committed at computed confidence | `RESOLVED` |
    | `REFUTED` | none (item 19 writes the negative belief) | `ESCALATED` |
    | `INCONCLUSIVE` | **none** -- no partial credit | `ESCALATED` |

    The span carries `action.predicate_id()`, byte-identical to the one the incident span
    already carried before anything executed. That pairing is what makes "declared before
    execution" checkable in the trace rather than asserted in a doc.

    `set_outcome` runs on every path, including the one where the commit was refused, so the
    span can never exit unrecorded (§8.1).
    """
    assert scratch.validated is not None
    validated = scratch.validated
    with telemetry.verification_outcome(
        predicate_id=action.predicate_id(validated),
        model=model,
        action_class=validated.action_class,
        target=validated.target,
        attempt=1,  # Item 20's bounded re-plan is what makes this ever exceed 1.
    ) as rec:
        outcome = _verification_outcome(verified)
        scratch.verification = outcome
        if outcome == "CONFIRMED":
            scratch.belief = await _commit_belief(
                scratch, domain=domain, agent_id=agent_id, now=now, client=client
            )
            scratch.outcome = "RESOLVED"
        else:
            scratch.outcome = "ESCALATED"
        rec.set_outcome(
            outcome=outcome,
            belief_written=scratch.belief is not None and scratch.belief.outcome == "COMMIT",
        )


async def _commit_belief(
    scratch: _Scratch, *, domain: str, agent_id: str, now: datetime, client: Any | None
) -> policy.BeliefCommit:
    """One §3.3 Evidence item, built from what code measured, handed to the Policy Engine.

    `source_id` names the read the executor actually performed, not the model that agreed
    with it, and `verifiable_by` names how a third party would redo it. That is the whole
    difference between evidence and testimony (§3.3).
    """
    assert scratch.validated is not None and scratch.post_state is not None
    validated = scratch.validated
    observed_at = now.astimezone(UTC).strftime(beliefs.TIMESTAMP)
    evidence = beliefs.Evidence(
        id=f"ev-{action.predicate_id(validated)}",
        source_id=f"firestore:{executor.SERVICES}/{validated.target}",
        source_class="verified_system_observation",
        observed_at=observed_at,
        ingested_at=observed_at,
        payload_hash=beliefs.payload_hash(asdict(scratch.post_state)),
        verifiable_by=f"re-read {executor.SERVICES}/{validated.target}",
    )
    return await policy.commit(
        entity=validated.target,
        domain=domain,
        status=BELIEF_STATUS,
        evidence=[evidence],
        agent_id=agent_id,
        now=now,
        client=client,
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
    model_verification: str | object = None,
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
            model_verification=model_verification or models.VERIFICATION,
        )

        sessions = InMemorySessionService()
        await sessions.create_session(
            app_name=_APP, user_id=incident_id, session_id=incident_id, state=state
        )
        runner = Runner(node=graph, app_name=_APP, session_service=sessions)
        try:
            async for _ in runner.run_async(
                user_id=incident_id,
                session_id=incident_id,
                new_message=types.Content(role="user", parts=[types.Part(text=trigger.signal)]),
            ):
                pass
        except Exception as error:  # noqa: BLE001 -- see below
            # ADK re-raises a failed node out of the root workflow. Letting that escape would
            # make a model timeout indistinguishable from "nothing happened": no incident
            # span outcome, no verification span, and a 500 from `/trigger`. §7.3's posture
            # is the opposite -- record it, escalate, learn nothing. `scratch.outcome`
            # already defaults to ESCALATED, and the block below emits the verification span
            # if an action had already executed.
            scratch.reasons.append(f"{type(error).__name__}: {error}")
            scratch.outcome = "ESCALATED"

        session = await sessions.get_session(
            app_name=_APP, user_id=incident_id, session_id=incident_id
        )
        state = {} if session is None else session.state
        if state.get("routed_to"):
            recorder.set_routing(
                domain=str(state["routed_domain"]),
                routed_to=str(state["routed_to"]),
            )
        if scratch.execution is not None and scratch.verification is None:
            # §7.3: "verification agent errors/timeouts -> treated as INCONCLUSIVE". ADK
            # stops the graph on a node failure rather than raising, so the `resolve` node
            # never ran -- and an executed action that reaches the end of the loop with no
            # verification span would read as an incident nobody checked. The control loop
            # owns this the way it owns the malformed count (§7.1).
            await _resolve(
                scratch,
                None,
                model=str(model_verification or models.VERIFICATION),
                domain=str(state.get("routed_domain", "")),
                agent_id=str(state.get("routed_to", "")),
                now=now,
                client=client,
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
        execution=scratch.execution,
        verification=scratch.verification,
        belief=scratch.belief,
    )
