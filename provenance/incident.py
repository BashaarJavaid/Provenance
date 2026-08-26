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

    authorize ?-> execute ?-> verification -> resolve ?-> halt (DONE)    (items 10, 20)
              |           `-> halt (execution failed)  `-> planner (REPLAN)
              `-> halt (HELD | DENIED)

Four properties this file is responsible for, and no other file is:

1. **Both §7.1 counts.** "No agent owns its own iteration count -- the control loop does, in
   code." The malformed count is `scratch.malformed_attempts` against `action.outcome_for()`,
   which shipped in item 6 with no caller for exactly this; the refutation count is
   `scratch.refuted_attempts` against `REFUTED_RETRY_BUDGET` (item 20). They are separate
   budgets because §7.1 states them as separate bullets: a schema slip and a failed remediation
   are different failures, and spending one on the other would be a coincidence of arithmetic.
2. **The root span.** Item 2 shipped four span shapes and recorded that the incident root
   "arrives with the Orchestrator in item 9". Everything else nests under it.
3. **Nothing reaches a state-mutating action except through the gateway** (§1.1 property 1).
   The authorize node calls `gateway.authorize()` and there is no second path; a diagnosis
   that never becomes a validated Action simply ends the incident. Since item 10 something
   downstream actually mutates state, and `executor.execute()` re-checks the decision's
   signature, outcome and subject rather than trusting that this node routed correctly.
4. **§7.2's rule for learning.** Memory learns from the two outcomes verification could
   *settle*, and from neither the third nor a missing one. `CONFIRMED` commits what worked;
   `REFUTED` commits the negative belief, because confirmed negative knowledge is real
   knowledge (item 19); `INCONCLUSIVE` writes nothing at all -- no partial credit.

Item 10 appended `execute`, the Verification Agent and `resolve`, and gave `authorize` a
`ctx.route`; nothing else about the item-9 graph changed. Item 20 gave `resolve` one too, and
added the one edge §7.2's `REFUTED` row has always described: back to the Planner, once.
`resolve` is the node that opens the `verification.outcome` span, because `belief_written` is
not known until the commit has been attempted -- so the `belief.commit` span nests inside it.

Agents and the graph are built per incident. Two runs must not share the per-invocation
tracing state in `_reasoning.py`, and a test must be able to substitute a fake model without
mutating a module global.
"""

from __future__ import annotations

import os
import uuid
from collections.abc import Callable, Mapping
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from typing import Any, cast, get_args

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from google.adk.agents import LlmAgent
from google.adk.agents.context import Context
from google.adk.runners import Runner
from google.adk.sessions import InMemorySessionService
from google.adk.workflow import START, Workflow
from google.genai import types

from provenance import (
    action,
    approvals,
    audit,
    beliefs,
    credentials,
    executor,
    gateway,
    ingest,
    models,
    policy,
    recall,
    registry,
    sanitizer,
    telemetry,
    tools,
)
from provenance.agents import (
    _reasoning,
    orchestrator,
    planner,
    sre_infra,
    supply_chain,
    verification,
)
from provenance.synthetic import company
from provenance.telemetry import IncidentOutcome, TargetKind, TriggerSignal, VerificationOutcome


@dataclass(frozen=True)
class Domain:
    """One routable domain: who owns it, what it covers, what it acts on, how it is built.

    The scope travels with the mapping because the Orchestrator's vocabulary and the routing
    table have to be the same list: a domain it can name but not reach, or reach but not name,
    is a silently unroutable incident. `target_kind` is item 21's addition and is read twice --
    `route` refuses a classification whose kind does not match the target's, and the seeders
    below use it to decide whether an incident is theirs.
    """

    agent_id: str
    scope: str
    target_kind: TargetKind
    build: Callable[..., LlmAgent]
    seed: Callable[..., dict[str, Any]]


# The one place a domain becomes routable. Item 21 adds one entry and one agent file; the graph,
# the seeding and the Orchestrator's vocabulary are all comprehended out of this dict, so a
# third domain adds nothing below it either. That is what item 22 measures.
DOMAINS: dict[str, Domain] = {
    sre_infra.DOMAIN: Domain(
        agent_id="sre-infra-agent",
        scope=sre_infra.DOMAIN_SCOPE,
        target_kind="service",
        build=sre_infra.build,
        seed=sre_infra.seed_state,
    ),
    supply_chain.DOMAIN: Domain(
        agent_id="supply-chain-agent",
        scope=supply_chain.DOMAIN_SCOPE,
        target_kind="supplier",
        build=supply_chain.build,
        seed=supply_chain.seed_state,
    ),
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
# RETRACTED are universal"). A constant because the control loop already knows this status
# deterministically -- a confirmed rollback teaches exactly one thing. Item 23's Memory Analyst
# is what first proposes a status a model had to derive, and this line is what it replaces.
BELIEF_STATUS = "CONFIG_REGRESSION_PRONE"

# And what a *refuted* one teaches (item 19). §7.2 words it "rollback of v42 did not resolve
# this deviation", which is a claim about the remediation and not about the cause: a rollback
# that failed to help does not show the config was innocent. Hence a status naming the
# remediation rather than the negation of the one above -- and hence `policy.commit()` rather
# than `policy.retract()`, since there is nothing here that the confirmed run got wrong
# (ADR-022, answering ADR-019's revisit clause).
REFUTED_STATUS = "ROLLBACK_INEFFECTIVE"

# §7.2's table as data: the outcomes memory learns from, and what each teaches. `INCONCLUSIVE`
# is absent rather than mapped to None, so "no partial credit" is the shape of this dict and
# not a branch someone can soften -- adding a third key is the only way to commit on ambiguity.
_LEARNS_FROM: dict[VerificationOutcome, str] = {
    "CONFIRMED": BELIEF_STATUS,
    "REFUTED": REFUTED_STATUS,
}

# §7.1: "one bounded re-plan after a `REFUTED` verification, then mandatory escalation. No agent
# owns its own iteration count -- the control loop does, in code" (item 20). It lives here and not
# beside `action.MALFORMED_RETRY_BUDGET` because that module is about the shape of an Action, and
# a remediation that executed and did not work is not a schema fact. Separate from the malformed
# budget on purpose: §7.1 states them as two bullets, and one incident may spend both.
REFUTED_RETRY_BUDGET = 1

_APP = "provenance"


@dataclass(frozen=True)
class Trigger:
    """One wake-on-event from the trigger stream (§5.3).

    Deliberately not a fifth §3 object. §3's four shapes "carry all authority-relevant data";
    a trigger carries none -- it is an observation that starts reasoning, and every field on
    it is re-derived from an authority before anything is decided. It is not persisted for
    the same reason: nothing reads an incident's trigger after the incident.

    `raw_content` is item 26's untrusted-content path and does not weaken that argument -- it
    strengthens it. It is the least authoritative field in the system: it is screened
    (`ingest.screen()`), then reduced to a `sanitizer.SanitizedFact` by an isolated model, and
    only the fact ever reaches a prompt. `None` is the ordinary case and means this deviation
    came from our own instrumentation, which is every incident before item 26.

    It is deliberately **not** on `POST /trigger`. Nothing over HTTP needs it until item 27's
    arc drives the demo, and a public field ahead of its caller is the shape `CLAUDE.md` §2
    forbids -- the same reasoning that kept `screen()` uncalled through item 25.
    """

    target: str
    signal: TriggerSignal
    observed_value: float
    observed_at: str
    raw_content: str | None = None


@dataclass(frozen=True)
class IncidentResult:
    """What one turn of the loop produced. `outcome` is the discriminator, not `decision`.

    The last three are `None` whenever the path was not taken -- a held incident executes
    nothing, one escalated before the gateway verifies nothing, and an INCONCLUSIVE
    verification writes no belief. Absent means the stage did not happen, never that it
    happened emptily.

    `ESCALATED` with a `belief` set is item 19's shape and is not a contradiction: a refuted
    remediation taught the fleet something and still left the incident open for a human.

    After item 20 an incident can make two attempts, and the four fields below report the **last**
    one -- the decision that was signed most recently, the action that ran most recently, and the
    belief version that stands. `refuted_attempts` is what says there was more than one; the trace
    is where each attempt is individually visible.
    """

    incident_id: str
    outcome: IncidentOutcome
    decision: gateway.Decision | None
    action: action.Action | None
    malformed_attempts: int
    refuted_attempts: int = 0
    execution: executor.ExecutionResult | None = None
    verification: VerificationOutcome | None = None
    belief: policy.BeliefCommit | None = None
    # Item 30: set on a `HELD` incident that parked, and on a resumed one, so a caller has the
    # id it needs to answer without going looking for it. `None` on every other outcome.
    approval_id: str | None = None


@dataclass
class _Scratch:
    """What the graph's nodes produce, kept out of session state.

    Session state holds only what an agent's instruction interpolates -- strings and numbers
    that survive being written to a session store. A `Decision` and an `Action` are neither,
    and round-tripping them through JSON would mean the object the caller inspects is not the
    object the gateway signed.
    """

    outcome: IncidentOutcome = "ESCALATED"
    # What memory handed this incident (§6.6, item 16): the entity beliefs found by exact
    # key, the class beliefs the index nominated and the store confirmed current, and the
    # nomination list before that filter. Item 15's ledger cites the *entity* ids off it, so
    # a later retraction of one can flag the action this incident authorized.
    recalled: recall.Recalled = field(default_factory=recall.Recalled)
    decision: gateway.Decision | None = None
    validated: action.Action | None = None
    proposal: dict[str, Any] | None = None
    malformed_attempts: int = 0
    refuted_attempts: int = 0
    reasons: list[str] = field(default_factory=list)
    execution: executor.ExecutionResult | None = None
    post_state: executor.ServiceState | None = None
    # When `post_state` was read, on the caller's clock. Per attempt, because §2.2's novelty
    # check compares `(source_id, observed_at)` pairs: two attempts stamped with the incident's
    # frozen `now` would be one observation twice, refused NO_NEW_EVIDENCE -- a *counted*
    # rejection, so an honest agent would lose standing for reporting its own failure (item 20).
    observed_at: datetime | None = None
    verification: VerificationOutcome | None = None
    belief: policy.BeliefCommit | None = None
    # Item 30. Set only on a HOLD, and it is the one thing a held incident leaves behind that
    # outlives the process: everything else on this object dies with the run.
    approval: approvals.Approval | None = None


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


def _seed_state(
    trigger: Trigger,
    planner_version: str,
    recalled: recall.Recalled,
    facts: sanitizer.SanitizedFact | None = None,
) -> dict[str, Any]:
    """Everything an agent instruction interpolates. Facts come from authorities, not the trigger.

    The trigger reports what was observed; the tier and the description are read from the
    entity model, which is the same authority `action.validate()` checks the Planner's declared
    tier against. A trigger that lied about a tier would change no prompt.

    Only the keys every incident shares live here. Whatever one domain's prompts name comes
    from that domain's own `seed_state()` and is merged in below -- item 21, and the reason it
    is a merge rather than a lookup is that state is seeded *before* the Orchestrator has
    classified anything, so there is no domain to key on yet. Every seeder runs on every
    incident and returns its own keys either way, which is what makes a mis-classification end
    `UNROUTABLE` at the routing node rather than raise at interpolation time.

    Seeders must therefore own **disjoint** key sets, since a later one would otherwise
    overwrite an earlier one's value. `tests/test_incident.py` asserts that they do.
    """
    entity = company.described(trigger.target)
    shared: dict[str, Any] = {
        "trigger_target": trigger.target,
        "trigger_signal": trigger.signal,
        "trigger_observed_value": trigger.observed_value,
        "trigger_observed_at": trigger.observed_at,
        "target_tier": entity.tier,
        "target_description": entity.description,
        # Each class with the entity kind it acts on, off the tool registry -- the authority,
        # not a hint. Observed live in item 20: told only that `DISABLE_COMPLIANCE_CHECKS`
        # existed, a Planner whose rollback had just been refuted proposed it against a
        # *service*, and `action.validate()` rejected it as it should. A model asked to pick an
        # action class from a list cannot pick well without knowing what each one acts on, and
        # this is the one place that fact was being dropped on the way to the prompt.
        "known_action_classes": ", ".join(
            f"{tool.action_class} (acts on a {tool.target_kind})" for tool in tools.TOOLS
        ),
        "planner_identity": f"{PLANNER_ID}@{planner_version}",
        "recall_summary": recalled.summary(),
        _reasoning.RECALL_BELIEF_IDS: list(recalled.belief_ids),
        _reasoning.RECALL_NOMINATED_IDS: list(recalled.nominated_ids),
        "malformed_feedback": "",
        # Item 20's channel, and deliberately not the one above: a schema rejection and a
        # remediation that ran and did not work are different things to tell a Planner, and
        # item 9's re-plan test asserts on its own key.
        "refutation_feedback": "",
        "diagnosis_summary": "",
        # The routed domain's own facts and predicate rules (item 21). Empty here and filled by
        # whichever seeder below owns this target's kind -- the one key seeders share, which is
        # why each returns it only for a target of its own kind.
        "planner_context": "",
        # Item 10. The Verification Agent's instruction interpolates all three, and the
        # `execute` node overwrites them with what it measured; seeded here because an
        # instruction naming a key that was never seeded fails at interpolation time.
        "success_predicate": "",
        "post_error_rate": trigger.observed_value,
        # A *post*-state nothing has measured yet, so it says so. `execute` overwrites all
        # three before it can route to VERIFY, and no other node reads them.
        "post_config_version": "unknown",
        # Item 26. Shared rather than per-domain: an untrusted inbound report is not a
        # supply-chain fact, and a third domain gets the channel without adding it. `"none"`
        # rather than absent, the way `malformed_feedback` and `planner_context` are seeded
        # empty -- an instruction naming a key that was never seeded fails at interpolation
        # time. This is the **only** value here derived from `trigger.raw_content`, which is
        # what makes item 26's `verify:` line checkable: the dict this function returns is
        # the complete set of values any frontier prompt interpolates.
        "sanitized_facts": facts.render() if facts is not None else "none",
    }
    for entry in DOMAINS.values():
        shared |= entry.seed(trigger)
    return shared


def build_graph(
    *,
    incident_id: str,
    trigger: Trigger,
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
    # `now` is the caller's clock and is frozen for the incident, which is what lets a test pin
    # every timestamp. An observation still has to say *when* it was made, so each attempt's is
    # that base advanced by the time that actually passed. Offline both attempts land inside one
    # second and truncate back to `now`; live they are a model call apart (item 20).
    wall_start = datetime.now(UTC)
    orchestrator_agent = orchestrator.build(
        model_orchestrator,
        agent_id=ORCHESTRATOR_ID,
        agent_version=ORCHESTRATOR_VERSION,
        domains=tuple((name, entry.scope) for name, entry in DOMAINS.items()),
    )
    # One node per registered domain, and the edge map below is comprehended out of the same
    # dict -- so a third domain adds no line here at all (item 21). Every agent is built even
    # though at most one will run: the graph is constructed before the Orchestrator classifies,
    # which is the same reason `_seed_state()` merges every seeder.
    domain_agents = {
        name: entry.build(model_domain, agent_id=entry.agent_id, agent_version="v1")
        for name, entry in DOMAINS.items()
    }
    planner_agent = planner.build(model_planner, agent_id=PLANNER_ID, agent_version=planner_version)
    verification_agent = verification.build(
        model_verification, agent_id=VERIFICATION_ID, agent_version=VERIFICATION_VERSION
    )

    def route(ctx: Context, classification: dict[str, Any]) -> None:
        """Registry lookup, not judgement. An unclassifiable incident ends here, visibly.

        The kind check is item 21's and is §7.3's default posture rather than a second
        judgement: a domain agent handed an entity of the wrong kind can only diagnose the
        placeholders its seeder returned for a target that is not its own, and a diagnosis
        built on `"n/a"` is worse than no diagnosis. It is also what makes the merged seeding
        above safe by construction instead of by the Orchestrator behaving.
        """
        domain = str(classification.get("domain", ""))
        entry = DOMAINS.get(domain)
        if entry is None:
            scratch.outcome = "UNROUTABLE"
            scratch.reasons.append(f"no agent registered for domain {domain!r}")
            ctx.route = "UNROUTABLE"
            return
        kind = company.described(trigger.target).kind
        if kind != entry.target_kind:
            scratch.outcome = "UNROUTABLE"
            scratch.reasons.append(
                f"domain {domain!r} acts on a {entry.target_kind}, but {trigger.target} is a {kind}"
            )
            ctx.route = "UNROUTABLE"
            return
        ctx.state["routed_domain"] = domain
        ctx.state["routed_to"] = entry.agent_id
        ctx.route = domain

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
        # A HOLD parks on a human (§2.1 stage 7) and a DENY is over. Only an approval
        # continues, and `executor.execute()` re-checks the signature anyway.
        if decision.outcome not in executor.APPROVING:
            if decision.outcome == "HOLD":
                assert scratch.proposal is not None  # `validate` routes here only on success
                try:
                    scratch.approval = await approvals.park(
                        incident_id=incident_id,
                        proposal=scratch.proposal,
                        subject=decision.subject,
                        held_signature=decision.signature,
                        # §6.2: ENTITY ids only, for the reason the ledger write below gives at
                        # length. The resumed row cites *these* rather than a fresh recall --
                        # what the fleet reasoned from, not what memory happens to say later.
                        entity_ids=scratch.recalled.entity_ids,
                        domain=str(ctx.state.get("routed_domain", "")),
                        routed_to=str(ctx.state.get("routed_to", "")),
                        trigger_target=trigger.target,
                        trigger_signal=trigger.signal,
                        trigger_observed_value=trigger.observed_value,
                        trace_id=telemetry.current_trace_id(),
                        now=now,
                        client=client,
                    )
                except approvals.ApprovalError as error:
                    # Fail closed (§7.3), the posture the ledger write below already takes: a
                    # held action nobody can find is one no human will ever be asked about,
                    # which turns §2.1 stage 7 into a silent drop. An escalation is visible;
                    # that is the whole difference.
                    scratch.reasons.append(f"{type(error).__name__}: {error}")
                    scratch.outcome = "ESCALATED"
            ctx.route = "HALT"
            return

        # §6.4's ledger (item 15). Approvals only -- "previously **authorized**" is what a
        # retraction flags, and a held or denied action never rested on anything.
        assert scratch.validated is not None  # `validate` routes here only on success
        try:
            await audit.record(
                agent_id=PLANNER_ID,
                action_class=scratch.validated.action_class,
                target=scratch.validated.target,
                outcome=decision.outcome,
                subject=decision.subject,
                signature=decision.signature,
                # ENTITY ids only, never the class beliefs recall also returned. §6.2 caps a
                # class belief as ADVISORY ONLY -- it may reorder what gets investigated and
                # may never be the evidence that authorizes an action -- and this field is the
                # record of what an action rested on. Citing one here would make §6.4's
                # retraction flag actions on grounds §6.2 says they could not have had.
                belief_ids=scratch.recalled.entity_ids,
                now=now,
                client=client,
            )
        except audit.AuditError as error:
            # Fail closed (§7.3): an authorization nothing recorded is one no retraction can
            # ever flag, which silently weakens §6.4. The belief store is the same Firestore,
            # so an incident that cannot write this could not have committed its belief either.
            scratch.reasons.append(f"{type(error).__name__}: {error}")
            scratch.outcome = "ESCALATED"
            ctx.route = "HALT"
            return

        ctx.route = "EXECUTE"

    async def execute(ctx: Context) -> None:
        """The one node that changes the world. Nothing here decides whether it may."""
        assert scratch.validated is not None and scratch.decision is not None
        try:
            scratch.execution = await executor.execute(
                scratch.validated, scratch.decision, client=client
            )
            scratch.post_state = await executor.read_state(scratch.validated.target, client=client)
            scratch.observed_at = now + (datetime.now(UTC) - wall_start)
        except executor.ExecutionError as error:
            # §7.3's default posture, made a row in that table: an execution that did not
            # happen verifies nothing and teaches nothing.
            scratch.outcome = "ESCALATED"
            scratch.reasons.append(f"{type(error).__name__}: {error}")
            ctx.route = "HALT"
            return
        # §9's third switch (item 19), read at execution time like the second one. It routes
        # past the Verification Agent *after* the action has really run, so this is genuinely
        # §7.3's "executed and never verified" row rather than a skipped remediation --
        # `run_incident()` below is what then emits the INCONCLUSIVE span, exactly as it does
        # for an agent that raised. Nothing here decides what the outcome is.
        if scratch.execution.verification_ambiguous:
            ctx.route = "HALT"
            return
        ctx.state["success_predicate"] = scratch.validated.success_predicate
        ctx.state["post_error_rate"] = scratch.post_state.error_rate
        ctx.state["post_config_version"] = scratch.post_state.config_version
        ctx.route = "VERIFY"

    async def resolve(ctx: Context, verification: dict[str, Any]) -> None:
        """§7.2's table: what was learned, whether the incident is over, and §7.1's second budget.

        The parameter name is load-bearing: ADK resolves a node's arguments out of session
        state by name, so this must be the agent's `output_key`. Same rule as `hand_off`'s
        `diagnosis` and `validate`'s `proposal`. It shadows the module of the same name,
        which is why `verification_agent` is bound above rather than built here.

        Only `REFUTED` is retried (item 20). `INCONCLUSIVE` is not: §7.2 gives it its own row --
        escalate, learn nothing -- and re-planning against measurements that settled nothing
        would be spending a model call on the same question.
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
        if scratch.verification != "REFUTED" or scratch.refuted_attempts > REFUTED_RETRY_BUDGET:
            ctx.route = "DONE"
            return
        assert scratch.validated is not None and scratch.post_state is not None
        # The Planner was told the fixture's version at wake time, and the rollback has moved it
        # since. Re-planning against a version the system no longer has is a re-plan aimed at the
        # wrong world, so the routed domain re-seeds its own block from the measured post-state.
        # Asking the domain rather than writing the key here is item 21: the version now lives
        # inside a block only that domain knows the shape of.
        routed = DOMAINS[str(ctx.state["routed_domain"])]
        ctx.state.update(routed.seed(trigger, deployed_version=scratch.post_state.config_version))
        # The kind constraint is restated deliberately, and observed live before it was. Told
        # only that its remediation had failed, the Planner concluded the config was innocent
        # and reached for the fleet's other tool -- `DISABLE_COMPLIANCE_CHECKS(inventory-api)`,
        # a supplier-scoped action aimed at a service. `action.validate()` rejected it as it
        # should, twice, and the incident escalated on the *malformed* budget having never made
        # its second attempt: §7.1's first bullet working and item 20 starved by it. Naming the
        # kind beside each class in `known_action_classes` was not enough on its own, because a
        # model that wants a different class resolves the conflict by keeping the target. So the
        # kind is stated here as the fact it is, read from the tool registry rather than written
        # down: item 21's supply-chain agent gets the right word for free.
        kind = tools.tool_for(scratch.validated.action_class).target_kind
        ctx.state["refutation_feedback"] = (
            "Your previous action executed and its result was REFUTED. You declared: "
            f"{scratch.validated.success_predicate!r}. After it ran, the measured error rate on "
            f"{scratch.validated.target} was {scratch.post_state.error_rate} and the deployed "
            f"config version was {scratch.post_state.config_version}. This is the final attempt "
            f"before the incident escalates to a human. Emit one action again. "
            f"{scratch.validated.target} is a {kind}, and every action class acts only on the "
            f"entity kind named beside it above, so a class for any other kind is not available "
            f"to you here. Re-proposing the same remediation is allowed and is often the right "
            "answer -- say what you expect to be different. An action outside those rules is "
            "rejected before authorization and spends this attempt on nothing.\n"
            # Item 11.5 gave the predicate a floor: a threshold at the nominal rate is
            # unsatisfiable however well the remediation works. Handing the Planner the *failed*
            # measurement introduces the opposite hazard, and it was observed on the first live
            # run that got this far: told the rate was 0.38, it declared "below 0.40" and its own
            # refutation became a CONFIRMED. So the retry's predicate needs a ceiling too. Both
            # bounds say one thing -- a predicate has to be satisfiable by success and
            # unsatisfiable by the failure it is meant to clear.
            "The success predicate you declare now must name an error-rate threshold strictly "
            f"between the nominal rate given above and {scratch.post_state.error_rate}, the rate "
            "measured after the failed attempt. A threshold at or above that measured value "
            "would be satisfied by the very state that refuted your last predicate."
        )
        ctx.route = "REPLAN"

    def halt() -> None:
        """The terminal node for every branch that stops before the fleet has learned."""

    return Workflow(
        name="incident",
        edges=[
            (START, orchestrator_agent),
            (orchestrator_agent, route),
            # The ignore is ADK's: its edge-map value type is a wide union that a homogeneous
            # `dict[str, LlmAgent]` does not unpack into, though every value here is a node.
            (route, {**domain_agents, "UNROUTABLE": halt}),  # type: ignore[dict-item]
            *((agent, hand_off) for agent in domain_agents.values()),
            (hand_off, planner_agent),
            (planner_agent, validate),
            (validate, {"AUTHORIZE": authorize, "REPLAN": planner_agent, "ESCALATE": halt}),
            (authorize, {"EXECUTE": execute, "HALT": halt}),
            (execute, {"VERIFY": verification_agent, "HALT": halt}),
            (verification_agent, resolve),
            # §7.1's second bounded loop, and the one §7.2's REFUTED row has always described.
            (resolve, {"REPLAN": planner_agent, "DONE": halt}),
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
    | `CONFIRMED` | `BELIEF_STATUS`, at computed confidence | `RESOLVED` |
    | `REFUTED` | `REFUTED_STATUS`, at computed confidence (item 19) | `ESCALATED` |
    | `INCONCLUSIVE` | **none** -- no partial credit | `ESCALATED` |

    The two committing rows go through the same `policy.commit()` and differ by one string, so
    the engine -- not this node -- decides what a refutation is allowed to write. On a service
    with no prior belief that is a v1 at 0.60; on one already carrying the confirmed status it
    is a status flip, which §6.3 refuses without a second source class. Both are correct, and
    neither is a branch here (ADR-022).

    The span carries `action.predicate_id()`, byte-identical to the one the incident span
    already carried before anything executed. That pairing is what makes "declared before
    execution" checkable in the trace rather than asserted in a doc. On a retried incident the
    incident span carries the *last* attempt's predicate, because it is set from
    `scratch.validated` when the root span closes; each attempt's own pairing is one
    `verification.outcome` span.

    `attempt` is `refuted_attempts + 1` rather than a second counter: a retry only ever follows a
    refutation, so "refutations so far" and "which attempt this is" are the same number offset by
    one. It is read *before* the outcome is known, which is why the increment below happens after.

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
        attempt=scratch.refuted_attempts + 1,
    ) as rec:
        outcome = _verification_outcome(verified)
        scratch.verification = outcome
        if outcome == "REFUTED":
            scratch.refuted_attempts += 1
        if outcome in _LEARNS_FROM:
            scratch.belief = await _commit_belief(
                scratch,
                status=_LEARNS_FROM[outcome],
                domain=domain,
                agent_id=agent_id,
                now=now,
                client=client,
            )
        scratch.outcome = "RESOLVED" if outcome == "CONFIRMED" else "ESCALATED"
        rec.set_outcome(
            outcome=outcome,
            belief_written=scratch.belief is not None and scratch.belief.outcome == "COMMIT",
        )


async def _commit_belief(
    scratch: _Scratch,
    *,
    status: str,
    domain: str,
    agent_id: str,
    now: datetime,
    client: Any | None,
) -> policy.BeliefCommit:
    """One §3.3 Evidence item, built from what code measured, handed to the Policy Engine.

    `source_id` names the read the executor actually performed, not the model that agreed
    with it, and `verifiable_by` names how a third party would redo it. That is the whole
    difference between evidence and testimony (§3.3).

    The id is `beliefs.evidence_id()` over the `(source_id, observed_at)` pair, not — as it
    was until item 13 — the success predicate's hash. Two incidents whose Planner happened to
    write the same predicate sentence share that hash while observing at different times, and
    `beliefs.append()` is create-if-absent, so the second write was discarded and the stored
    document kept the first run's timestamp. §2.2's novelty check reads those documents.

    `observed_at` is the attempt's own read time (item 20), falling back to `now` for a caller
    that reaches here with no execution behind it. It is the same defect one level up: two
    attempts of one incident stamped with the frozen `now` are one observation cited twice, and
    §2.2 would refuse the second NO_NEW_EVIDENCE -- a counted rejection, so an agent would lose
    standing for honestly reporting that its own remediation failed twice.
    """
    assert scratch.validated is not None and scratch.post_state is not None
    validated = scratch.validated
    observed_at = (scratch.observed_at or now).astimezone(UTC).strftime(beliefs.TIMESTAMP)
    source_id = f"firestore:{executor.SERVICES}/{validated.target}"
    evidence = beliefs.Evidence(
        id=beliefs.evidence_id(source_id, observed_at),
        source_id=source_id,
        source_class="verified_system_observation",
        observed_at=observed_at,
        ingested_at=observed_at,
        payload_hash=beliefs.payload_hash(asdict(scratch.post_state)),
        verifiable_by=f"re-read {executor.SERVICES}/{validated.target}",
    )
    return await policy.commit(
        entity=validated.target,
        domain=domain,
        status=status,
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
    embed: recall.Embedder | None = None,
    sanitizer_client: Any | None = None,
) -> IncidentResult:
    """One trigger, one incident, one root span. Never raises on a bad proposal.

    It **does** raise on untrusted content that cannot be made safe, and the two are not in
    tension: a bad proposal is a result the loop is designed to produce, whereas ingest
    failing is §7.3's "ingest halts". Both the screening and the sanitizing happen *before*
    the incident span opens, so a halt leaves no incident id, no span and no record -- which
    is what "halts" has to mean. An incident span carrying a halt outcome would assert that a
    reasoning loop ran when none did.

    The model arguments exist so tests can substitute a fake `BaseLlm`; unset, each falls
    back to its `models.py` role string. `embed` is the same arrangement for item 16's recall
    index -- unset, it calls Vertex. Everything else the loop needs -- the Planner's
    version and public key -- is read from the registry at request time (§1.1 property 4),
    never from a constant here.
    """
    now = now or datetime.now(UTC)

    # §5.1 then §5.2, in that order and both outside the span below. Neither is one of the
    # decisions §8.1's vocabulary carries, and a plain step here is `recall`'s precedent
    # (§5.3): the graph stays the graph, so ADR-007's park/resume and item 20's re-plan edge
    # are untouched by an ingest concern.
    facts: sanitizer.SanitizedFact | None = None
    if trigger.raw_content is not None:
        verdict = await ingest.screen(trigger.raw_content)
        if verdict.blocked:
            raise ingest.ContentBlocked(verdict.filters_matched)
        facts = await sanitizer.sanitize(trigger.raw_content, client=sanitizer_client)

    incident_id = f"inc-{uuid.uuid4().hex[:12]}"
    scratch = _Scratch()

    with telemetry.incident(
        incident_id=incident_id,
        trigger_target=trigger.target,
        trigger_signal=trigger.signal,
    ) as recorder:
        agent = await registry.get_agent(PLANNER_ID, client=client)
        entity = company.described(trigger.target)
        recalled = await recall.recall(
            trigger.target,
            recall.query_text(
                target=trigger.target,
                signal=trigger.signal,
                kind=entity.kind,
                tier=entity.tier,
                description=entity.description,
                observed_value=trigger.observed_value,
            ),
            client=client,
            embed=embed,
        )
        scratch.recalled = recalled
        state = _seed_state(trigger, agent.version, recalled, facts)

        graph = build_graph(
            incident_id=incident_id,
            trigger=trigger,
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

    return _result(incident_id, scratch)


async def resume(
    approval_id: str,
    *,
    verdict: gateway.HumanVerdict,
    approver: str,
    now: datetime | None = None,
    client: Any | None = None,
    model_verification: str | object = None,
) -> IncidentResult:
    """§2.1 stage 7's other half: a human answers a parked action (item 30).

    The second public coroutine, beside `run_incident()`. It runs the remainder of the loop the
    hold interrupted -- authorize, then execute, verify and learn -- and nothing before it: the
    classification, the diagnosis and the plan were made once, by the fleet, and re-reasoning
    them because a person took five minutes would answer a different question than the one that
    was asked. Which is why no model runs here except the Verification Agent, and only on the
    approve path.

    **A new root span, the same incident id.** The park's own trace belongs to a process that
    may be days gone -- and the trace UI's span buffer is in-process, so a resumed leg attached
    to a dead trace would render as a fragment with no parent, which is the opposite of what
    §8.2 needs. It opens `telemetry.incident()` with the three wake-on-event facts the parked
    record carried, so the two legs join on `incident_id`, and the parked `trace_id` is the
    pointer back (`ADR-032` §6).

    **A fresh clock, deliberately.** `now` defaults to real wall time rather than the parked
    incident's frozen one. A post-state measured after a park did not happen at trigger time,
    and §2.2's novelty check compares `(source_id, observed_at)` pairs -- backdating it is the
    same defect `_Scratch.observed_at` already carries a comment about (item 20).

    Denials stop here and are recorded. Approvals go on to `executor.execute()`, which
    re-checks the signature `gateway.resolve()` just produced, and then to the same `_resolve`
    every other verification runs through: a resumed incident learns on exactly the terms
    §7.2 sets for every other one, or it is not the same loop.
    """
    now = now or datetime.now(UTC)
    approvals.check_approver(approver)
    record = await approvals.get(approval_id, client=client)
    if record.state != "PARKED":
        raise approvals.ApprovalNotPending(
            f"{approvals.COLLECTION}/{approval_id}: already {record.state}"
        )

    scratch = _Scratch()
    scratch.approval = record
    # The stored signal is a plain string on the way out of Firestore, and `telemetry.incident()`
    # takes the closed vocabulary. Checking it rather than casting is the posture the telemetry
    # module's own `_enum()` takes: a stored value outside the vocabulary is a malformed record,
    # not something to coerce into the nearest legal word.
    if record.trigger_signal not in get_args(TriggerSignal):
        raise approvals.ApprovalError(
            f"{approvals.COLLECTION}/{approval_id}: unknown trigger_signal "
            f"{record.trigger_signal!r}"
        )
    signal = cast(TriggerSignal, record.trigger_signal)
    with telemetry.incident(
        incident_id=record.incident_id,
        trigger_target=record.trigger_target,
        trigger_signal=signal,
    ) as recorder:
        recorder.set_routing(domain=record.domain, routed_to=record.routed_to)

        # The gateway, again and from scratch: `resolve()` re-validates the stored proposal and
        # recomputes §4.2 rather than reading either back. `scratch.validated` is therefore the
        # gateway's Action, not one this function parsed -- there is still exactly one place a
        # proposal becomes an action anyone may act on.
        decision = await gateway.resolve(
            record.proposal,
            subject=record.subject,
            verdict=verdict,
            approver=approver,
            now=now,
            client=client,
        )
        scratch.decision = decision
        scratch.outcome = _OUTCOME_FOR[decision.outcome]
        try:
            scratch.validated = action.validate(record.proposal)
        except action.ActionError:
            scratch.validated = None  # a schema denial above; there is nothing to execute

        # §6.4's ledger, on **both** verdicts, which is where a resumed incident departs from
        # item 15's rule and why: "previously authorized" excluded a held action because nobody
        # had been asked, and a human answering is the case that exclusion was never about.
        # The row cites the entity beliefs the *parked* recall resolved (item 16), so a later
        # retraction still finds an action a human approved days after the fleet proposed it.
        if scratch.validated is not None:
            try:
                await audit.record(
                    agent_id=PLANNER_ID,
                    action_class=scratch.validated.action_class,
                    target=scratch.validated.target,
                    outcome=decision.outcome,
                    subject=decision.subject,
                    signature=decision.signature,
                    belief_ids=record.entity_ids,
                    approver=approver,
                    now=now,
                    client=client,
                )
            except audit.AuditError as error:
                # §7.3, and item 15's reasoning unchanged: an authorization nothing recorded is
                # one no retraction can ever flag. The park stays PARKED so the human can answer
                # again once the ledger is writable.
                scratch.reasons.append(f"{type(error).__name__}: {error}")
                recorder.set_outcome(outcome="ESCALATED", malformed_attempts=0, predicate_id=None)
                return _result(record.incident_id, scratch)

        if decision.outcome in executor.APPROVING and scratch.validated is not None:
            await _execute_and_learn(
                scratch,
                record,
                model_verification=model_verification or models.VERIFICATION,
                now=now,
                client=client,
            )

        # Terminal last: until this lands the record is still answerable, which is the right
        # way round. A resolved park whose action never ran would be an action nobody can
        # authorize any more, and §7.3 has no row for that.
        scratch.approval = await approvals.resolve(
            record.id,
            state="APPROVED" if verdict == "approve" else "DENIED",
            approver=approver,
            now=now,
            client=client,
        )
        recorder.set_outcome(
            outcome=scratch.outcome,
            malformed_attempts=0,
            predicate_id=(
                None if scratch.validated is None else action.predicate_id(scratch.validated)
            ),
        )
    return _result(record.incident_id, scratch)


async def _execute_and_learn(
    scratch: _Scratch,
    record: approvals.Approval,
    *,
    model_verification: str | object,
    now: datetime,
    client: Any | None,
) -> None:
    """The approved tail of the loop: execute, read the post-state, verify, learn.

    The same steps `run_incident()`'s `execute` and `resolve` nodes take, through the same
    functions and the same Verification Agent -- built from `verification.build()` and run by
    an ADK `Runner`, so the resumed leg emits the same `reasoning.chain` span the first leg
    would have. A two-node graph rather than a rebuilt five-node one: the graph's job is
    routing, and an approved action has exactly one path left through it (`ADR-032` §7).

    §7.3's rows are the ones the `execute` node already has. An execution that failed verifies
    nothing; an ambiguous post-state, or a Verification Agent that errored, is `INCONCLUSIVE`
    and writes no belief -- which is `_resolve(scratch, None, ...)`, exactly as `run_incident()`
    does for an agent that raised.
    """
    assert scratch.validated is not None and scratch.decision is not None
    try:
        scratch.execution = await executor.execute(
            scratch.validated, scratch.decision, client=client
        )
        scratch.post_state = await executor.read_state(scratch.validated.target, client=client)
        scratch.observed_at = now
    except executor.ExecutionError as error:
        scratch.outcome = "ESCALATED"
        scratch.reasons.append(f"{type(error).__name__}: {error}")
        return

    verification_agent = verification.build(
        model_verification, agent_id=VERIFICATION_ID, agent_version=VERIFICATION_VERSION
    )

    async def resolve_node(ctx: Context, verification: dict[str, Any]) -> None:
        """`run_incident()`'s `resolve` node minus item 20's retry edge, which a resume has no
        room for: a re-plan would need the Planner, and the Planner's proposal is what the
        human answered. A `REFUTED` resume escalates, which is where the retry budget ends up
        anyway."""
        await _resolve(
            scratch,
            verification,
            model=_reasoning.model_name(verification_agent),
            domain=record.domain,
            agent_id=record.routed_to,
            now=now,
            client=client,
        )
        ctx.route = "DONE"

    if scratch.execution.verification_ambiguous:
        # §7.3's "executed and never verified" row, reached the way the `execute` node reaches
        # it: measurements that settle nothing are not a question worth a model call.
        await _resolve(
            scratch,
            None,
            model=str(model_verification),
            domain=record.domain,
            agent_id=record.routed_to,
            now=now,
            client=client,
        )
        return

    graph = Workflow(
        name="incident_resume",  # ADK requires a Python identifier; `build_graph()`'s is "incident"
        edges=[
            (START, verification_agent),
            (verification_agent, resolve_node),
            (resolve_node, {"DONE": _halt}),
        ],
    )
    sessions = InMemorySessionService()
    await sessions.create_session(
        app_name=_APP,
        user_id=record.incident_id,
        session_id=record.id,
        # Exactly what §5.8's instruction interpolates, and nothing else: the resumed leg has
        # no diagnosis, no plan and no recall to seed, because none of them runs again.
        state={
            "trigger_target": record.trigger_target,
            "trigger_observed_value": record.trigger_observed_value,
            "success_predicate": scratch.validated.success_predicate,
            "post_error_rate": scratch.post_state.error_rate,
            "post_config_version": scratch.post_state.config_version,
        },
    )
    runner = Runner(node=graph, app_name=_APP, session_service=sessions)
    try:
        async for _ in runner.run_async(
            user_id=record.incident_id,
            session_id=record.id,
            new_message=types.Content(role="user", parts=[types.Part(text=record.trigger_signal)]),
        ):
            pass
    except Exception as error:  # noqa: BLE001 -- `run_incident()`'s reasoning, unchanged
        scratch.reasons.append(f"{type(error).__name__}: {error}")
    if scratch.verification is None:
        # §7.3: "verification agent errors/timeouts -> treated as INCONCLUSIVE". An executed
        # action that reaches the end with no verification span would read as one nobody checked.
        await _resolve(
            scratch,
            None,
            model=str(model_verification),
            domain=record.domain,
            agent_id=record.routed_to,
            now=now,
            client=client,
        )


def _halt() -> None:
    """The resume graph's terminal node. `build_graph()`'s `halt` is the same thing, scoped."""


def _result(incident_id: str, scratch: _Scratch) -> IncidentResult:
    """One `_Scratch` as the frozen result both public coroutines return."""
    return IncidentResult(
        incident_id=incident_id,
        outcome=scratch.outcome,
        decision=scratch.decision,
        action=scratch.validated,
        malformed_attempts=scratch.malformed_attempts,
        refuted_attempts=scratch.refuted_attempts,
        execution=scratch.execution,
        verification=scratch.verification,
        belief=scratch.belief,
        approval_id=None if scratch.approval is None else scratch.approval.id,
    )
