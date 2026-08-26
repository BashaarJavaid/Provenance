"""The Agent Gateway — §2.1's action pipeline, the only path to a state-mutating action.

`ARCHITECTURE.md` §1.1's first load-bearing property: "There is no direct path from any
reasoning agent to a state-mutating action. The gateway is architecturally the only path.
If a second path exists, the security story collapses." This module is that path.

**There are two public doors, and item 30 is why.** `authorize()` runs §2.1 stages 1-6 on a
proposal an agent just made. `resolve()` runs §2.1 stage 7 -- a human's answer to an action
this gateway already held -- because re-running `authorize()` after an approval would
deterministically HOLD it again: §4.2 is a lookup, and nothing about it changes when a person
says yes. The human's authority has to enter the pipeline somewhere, and property 1 says it
enters here or the property is false. That is the same shape the Policy Engine took when
`expire()` joined `commit()` and `retract()`: one authority, one module, more than one
question it can be asked. Neither door executes anything.

Both doors take an untrusted `object`, not a validated `Action`, and run §2.1 stage 1
themselves. That is deliberate: it is what makes `DENY(stage="schema")` reachable, and it
means there is no way to reach the risk table without having passed validation, because
every door does both.

The stages, and where each one's denial comes from:

| Stage | Authority | Denies with |
|---|---|---|
| `schema` | `action.validate()` (§3.1) | `SCHEMA_INVALID` |
| `registry` | `registry.get_agent()`, read fresh (§1.1 #4) | `REGISTRY_UNAVAILABLE`, `AGENT_NOT_REGISTERED`, `STANDING_SUSPENDED` |
| `identity` | `credentials.verify()` against the stored `public_key` | `CREDENTIAL_INVALID`, `CREDENTIAL_EXPIRED` |
| `abac` | `agent.tool_scope`, then the Portunus ABAC condition | `TOOL_SCOPE` |
| `risk` | `risk.score()` — the §4.2 table, never a model | `RISK_THRESHOLD` (holds, never denies) |
| `human` | the store operations manager, via `resolve()` (§2.1 stage 7) | `HUMAN_DENIED` (and `HUMAN_APPROVED`, the one reason that is not a refusal) |

**Physical order differs from §2.1's numbering, once.** §2.1 lists identity as stage 2 and
the registry read as stage 3, but the public key the credential is checked against *is* a
registry field — so the read has to happen first. The `stage=` recorded on a denial is
§2.1's, so the audit stream reads the way the document does.

**RBAC and ABAC are separate things and are implemented separately.** Tool scope is
role-based — "is this action class within this agent's declared tool scope?" — and is a
membership test. The standing rule is attribute-based, and is compiled and evaluated by
PortunusMCP's `abac` primitives (`docs/adr/ADR-004`'s consumed surface). Portunus's
condition grammar has no `in` operator, so expressing scope through it would mean
synthesising an OR-chain from a list to do what `in` already does.

**A denial is never about the score.** `risk.band()` returns APPROVE, APPROVE_NOTIFY or
HOLD and nothing else; every DENY here comes from *who is asking* — identity, registry
standing, or scope. The score's worst answer is "a human decides".

**The signing key is ephemeral per process.** See `_signing_key()`.

Every outcome, including every denial, is ECDSA-signed and emitted on one
`provenance.authorization.decision` span (§2.1 stage 6, §8.1). Nothing here executes
anything: an APPROVE is a return value, and item 10 owns the executor.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Literal

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from services.gateway import abac, signing

from provenance import action, credentials, registry, risk, telemetry
from provenance.telemetry import AuthOutcome, AuthStage

# A closed vocabulary, checked the way telemetry's own enums are. `decision.reason` lands on
# a span, and §8.1 admits "identifiers, hashes, enums and numbers only — never content"; a
# free string is one careless call site away from putting model prose in the trace. Item 28's
# registry panel and item 31's approval card both render from this fixed set.
DecisionReason = Literal[
    "SCHEMA_INVALID",
    "CREDENTIAL_INVALID",
    "CREDENTIAL_EXPIRED",
    "REGISTRY_UNAVAILABLE",
    "AGENT_NOT_REGISTERED",
    "STANDING_SUSPENDED",
    "STANDING_DEGRADED",
    "TOOL_SCOPE",
    "RISK_THRESHOLD",
    # Item 30's two, and the only pair in this vocabulary that report what a *person* decided
    # rather than what a check found. They can only ever accompany `stage="human"`.
    "HUMAN_APPROVED",
    "HUMAN_DENIED",
]

# What a human may answer. A closed pair, checked the way every other vocabulary here is: the
# HTTP boundary hands this straight through, and "approve" is the only string that approves.
HumanVerdict = Literal["approve", "deny"]

# The one attribute condition, compiled once. `abac.ATTRIBUTE_ROOTS` is a fixed
# {identity, tool, context, risk} (pinned by tests/test_portunus_surface.py), and standing
# maps onto `identity` cleanly. SUSPENDED has already terminated by the time this is
# evaluated, so "not satisfied" here means DEGRADED — which holds rather than denies.
_GOOD_STANDING = abac.compile_condition("identity.standing == 'GOOD'")


@dataclass(frozen=True)
class Decision:
    """What the gateway decided, and the signature that makes it checkable.

    Not PortunusMCP's `decision.Decision`. Its vocabulary is allow / deny / challenge /
    human_approval_required, which has no room for §4.2's APPROVE vs APPROVE_NOTIFY split
    and one value (`challenge`) this system has no concept of. ROADMAP item 0.5 left the
    choice open; `telemetry.AuthOutcome` had already made it, and reusing those Literals as
    the field types here means the returned object and the emitted span cannot drift.

    `score` is `None` exactly when the pipeline terminated before the risk table — which is
    every denial except a scope denial, and is why `telemetry.set_risk()` is separate from
    `set_outcome()`.
    """

    outcome: AuthOutcome
    stage: AuthStage
    reason: DecisionReason
    subject: str  # "agent@version|action_class|target" — what this decision is *about*
    score: risk.RiskScore | None
    signature: str  # "ecdsa:<hex>", over every field above


class DecisionInvalid(Exception):
    """A decision's signature does not verify against the gateway's public key."""


@dataclass(frozen=True)
class _Verdict:
    """The pipeline's result before it is signed and emitted. Internal."""

    outcome: AuthOutcome
    stage: AuthStage
    reason: DecisionReason
    proposal: action.Action | None = None
    agent: registry.Agent | None = None
    score: risk.RiskScore | None = None


# ponytail: the gateway's signing key is generated per process and never persisted. That is
# enough for the property that matters here — a decision in the audit stream can be checked
# against public_key_pem() from the same run — but signatures do not survive a Cloud Run
# restart. Upgrade path if they must: load a PEM from Secret Manager, keeping this as the
# fallback so CI and local runs still need no secret. ADR-010 declined Firestore and a
# gitignored .keys/ directory for agent keys, and both are wrong here for the same reasons.
_key: ec.EllipticCurvePrivateKey | None = None


def _signing_key() -> ec.EllipticCurvePrivateKey:
    global _key
    if _key is None:
        _key = signing.generate_private_key()
    return _key


def public_key_pem() -> str:
    """The key every decision from this process is signed with, as a PEM string."""
    pem: bytes = signing.public_pem(_signing_key().public_key())
    return pem.decode()


def _subject(agent_id: str, agent_version: str, proposal: action.Action | None) -> str:
    """What a decision is about, as one string, so the signature is bound to it.

    Without this the signature covers only the verdict, and a signed APPROVE could be
    lifted from a rollback onto a compliance-check disable. `authorize()` passes the agent
    halves off the *credential*, not off `proposed_by`, because the credential is the
    authenticated one; `resolve()` passes them off the parked subject, which is the same
    string this function produced when the hold was signed.
    """
    action_class = "" if proposal is None else proposal.action_class
    target = "" if proposal is None else proposal.target
    return f"{agent_id}@{agent_version}|{action_class}|{target}"


def _agent_halves(subject: str) -> tuple[str, str]:
    """Split `"agent@version|class|target"` back into its agent id and version.

    Only the two halves are taken. The action class and target in a stored subject are
    *not* read back: `resolve()` re-derives those from the re-validated proposal, so a
    tampered `proposals` field cannot inherit the identity the gateway signed.
    """
    identity = subject.partition("|")[0]
    agent_id, _, agent_version = identity.partition("@")
    return agent_id, agent_version


def _decision_hash(
    outcome: str, stage: str, reason: str, subject: str, score: risk.RiskScore | None
) -> str:
    """The hash a decision is signed over. Portunus's `signing.sign()` wants a hash string."""
    components = (
        ""
        if score is None
        else f"{score.base},{score.criticality},{score.blast},{score.irreversibility},{score.score}"
    )
    return hashlib.sha256(f"{outcome}|{stage}|{reason}|{subject}|{components}".encode()).hexdigest()


def verify_decision(decision: Decision, public_key_pem_: str) -> None:
    """Raise `DecisionInvalid` unless the decision was signed by that key, unaltered.

    This is what makes "every outcome, including denials, signed into the audit stream" a
    checkable claim rather than a decoration: `scripts/verify_gateway.py` runs it against a
    live decision, and the tests run it against a mutated one.
    """
    if not decision.signature.startswith("ecdsa:"):
        raise DecisionInvalid("signature: expected an `ecdsa:<hex>` value")
    try:
        raw = bytes.fromhex(decision.signature.removeprefix("ecdsa:"))
    except ValueError as exc:
        raise DecisionInvalid(f"signature: not hex ({exc})") from exc
    public_key = serialization.load_pem_public_key(public_key_pem_.encode())
    if not isinstance(public_key, ec.EllipticCurvePublicKey):
        raise DecisionInvalid("public_key: not an EC public key")
    expected = _decision_hash(
        decision.outcome, decision.stage, decision.reason, decision.subject, decision.score
    )
    if not signing.verify(public_key, raw, expected):
        raise DecisionInvalid(f"signature does not verify for {decision.subject}")


async def _decide(
    proposal: object,
    credential: credentials.Credential,
    *,
    now: datetime,
    client: Any | None,
) -> _Verdict:
    """§2.1's stages, in the order they can physically run. The earliest outcome wins."""
    # Stage 1 — schema. Nothing below is consulted if this fails (§7.1: "before the gateway
    # ever sees it" means before identity, the registry read, ABAC and the risk table).
    try:
        validated = action.validate(proposal)
    except action.ActionError:
        return _Verdict("DENY", "schema", "SCHEMA_INVALID")

    # Stage 3, run early — the public key stage 2 needs is a field on this record. Read
    # fresh on every call, never cached (§1.1 #4); every failure denies (§7.3 fail-closed).
    try:
        agent = await registry.get_agent(credential.agent_id, client=client)
    except registry.AgentNotRegistered:
        return _Verdict("DENY", "registry", "AGENT_NOT_REGISTERED", validated)
    except registry.RegistryError:
        return _Verdict("DENY", "registry", "REGISTRY_UNAVAILABLE", validated)

    # Stage 2 — identity. The credential must authenticate *this* agent at *this* version,
    # and the action must be the one it accompanies: without the last check an agent could
    # present its own valid credential alongside an action attributed to somebody else.
    if credential.agent_version != agent.version:
        return _Verdict("DENY", "identity", "CREDENTIAL_INVALID", validated, agent)
    if validated.proposed_by != f"{credential.agent_id}@{credential.agent_version}":
        return _Verdict("DENY", "identity", "CREDENTIAL_INVALID", validated, agent)
    try:
        credentials.verify(credential, agent.public_key, now=now)
    except credentials.CredentialExpired:
        return _Verdict("DENY", "identity", "CREDENTIAL_EXPIRED", validated, agent)
    except credentials.CredentialError:
        return _Verdict("DENY", "identity", "CREDENTIAL_INVALID", validated, agent)

    # Stage 3 — standing. §2.1: "`SUSPENDED` is denied outright". No score: a denial owes
    # the human no arithmetic, and §8.1 wants the span to carry none.
    if agent.standing == "SUSPENDED":
        return _Verdict("DENY", "registry", "STANDING_SUSPENDED", validated, agent)

    # Stage 4a — RBAC. Role scope is a membership test; that is what role-based means.
    if validated.action_class not in agent.tool_scope:
        return _Verdict("DENY", "abac", "TOOL_SCOPE", validated, agent)

    # Stage 4b — ABAC, through the Portunus primitive. `missing` is always empty here: the
    # one path the condition names is supplied on the line above it. Were it ever not, the
    # library returns not-satisfied, which lands on the hold branch — fail-closed either way.
    satisfied, _missing = abac.evaluate(_GOOD_STANDING, {"identity.standing": agent.standing})

    # Stage 5 — the §4.2 table. Computed even for a DEGRADED hold, because item 31's
    # approval card renders the component-by-component arithmetic for everything a human is
    # asked to approve, and "held despite scoring 2" is the sentence that beat needs.
    scored = risk.score(validated)
    if not satisfied:
        # DEGRADED — SUSPENDED already returned above. §3.4: "a DEGRADED agent's proposals
        # require human approval regardless of risk score". The stage is `registry` because
        # that is what caused it; the score rides along anyway.
        return _Verdict("HOLD", "registry", "STANDING_DEGRADED", validated, agent, scored)

    # Stage 6 — the bands.
    return _Verdict(risk.band(scored.score), "risk", "RISK_THRESHOLD", validated, agent, scored)


async def authorize(
    proposal: object,
    credential: credentials.Credential,
    *,
    now: datetime,
    client: Any | None = None,
) -> Decision:
    """Run §2.1 on one proposal. Returns a signed Decision; never raises on a bad proposal.

    Every terminal outcome is a `Decision`, because a raised exception is something a caller
    can swallow into "nothing happened" — and "nothing happened" must never be reachable
    from a denial that should have been recorded (§7.3).
    """
    verdict = await _decide(proposal, credential, now=now, client=client)
    return _finish(verdict, agent_id=credential.agent_id, agent_version=credential.agent_version)


async def resolve(
    proposal: object,
    *,
    subject: str,
    verdict: HumanVerdict,
    approver: str,
    now: datetime,
    client: Any | None = None,
) -> Decision:
    """§2.1 stage 7 — the human's answer to a parked action, as a signed Decision (item 30).

    The second public coroutine, and the reason there is one: re-running `authorize()` on an
    approved proposal would deterministically HOLD it again, because §4.2 is a lookup and
    nothing about it changes when a person says yes. The human's authority has to enter the
    pipeline somewhere, and §1.1 property 1 says the somewhere is here — a resume that
    signed its own approval anywhere else would be the second path that property forbids.

    **It trusts nothing the queue stored.** It takes `object`, the way `authorize()` does,
    and re-runs §2.1 stage 1 itself; it re-reads the registry (§1.1 property 4 -- a resume is
    a request); and it recomputes §4.2 from the re-validated action rather than reading back
    the score the hold carried. That is not belt-and-braces: `_signing_key()` is generated
    per process, so a park that outlived its process cannot have its own signature checked,
    and the answer is to make the stored record an *input* to the pipeline rather than a
    conclusion. Tampering with a parked proposal therefore changes its score deterministically
    instead of slipping past a check, and `approver` never touches the arithmetic.

    No credential is involved and none is minted. `credentials.CREDENTIAL_TTL_SECONDS` is 300,
    so the agent's credential expired inside any park worth the name; minting a fresh one on
    its behalf would be the gateway forging the identity it exists to check. The authority
    carried here is the gateway's own signature over a human's verdict, which is why the
    `subject` keeps the agent halves the hold was signed with -- the decision is still *about*
    that agent's action.

    Fail-closed before the verdict is ever consulted, in this order: a proposal that no longer
    validates, an unreadable registry, an agent that no longer exists, an agent rotated to a
    new version since the park, and an agent the fleet has since SUSPENDED all deny -- a human
    may not approve an action for an agent the fleet has stopped trusting. Reasoning in
    `docs/adr/ADR-032`.
    """
    resolved = await _re_decide(proposal, subject, verdict, client=client)
    agent_id, agent_version = _agent_halves(subject)
    return _finish(resolved, agent_id=agent_id, agent_version=agent_version)


async def _re_decide(
    proposal: object, subject: str, verdict: HumanVerdict, *, client: Any | None
) -> _Verdict:
    """`_decide()`'s stages minus the ones a park cannot carry, plus the human's answer."""
    try:
        validated = action.validate(proposal)
    except action.ActionError:
        return _Verdict("DENY", "schema", "SCHEMA_INVALID")

    agent_id, agent_version = _agent_halves(subject)
    try:
        agent = await registry.get_agent(agent_id, client=client)
    except registry.AgentNotRegistered:
        return _Verdict("DENY", "registry", "AGENT_NOT_REGISTERED", validated)
    except registry.RegistryError:
        return _Verdict("DENY", "registry", "REGISTRY_UNAVAILABLE", validated)

    # The park's own identity check. `authorize()` compares the *credential's* version against
    # the registry's; there is no credential here, so the comparison is against the version the
    # hold was signed with. An agent rotated during a park proposed this as somebody it no
    # longer is, and `--rotate` is a human act -- the same posture as a suspension.
    if agent_version != agent.version:
        return _Verdict("DENY", "identity", "CREDENTIAL_INVALID", validated, agent)
    if agent.standing == "SUSPENDED":
        return _Verdict("DENY", "registry", "STANDING_SUSPENDED", validated, agent)

    # §4.2 recomputed, never read back. It rides along on both verdicts because item 31's card
    # renders the arithmetic for everything a human was asked about, including what they denied.
    scored = risk.score(validated)
    if verdict == "approve":
        return _Verdict("APPROVE", "human", "HUMAN_APPROVED", validated, agent, scored)
    return _Verdict("DENY", "human", "HUMAN_DENIED", validated, agent, scored)


def _finish(verdict: _Verdict, *, agent_id: str, agent_version: str) -> Decision:
    """Sign one verdict and emit its §8.1 span. The tail both public doors share."""
    proposed = verdict.proposal
    subject = _subject(agent_id, agent_version, proposed)
    signature: bytes = signing.sign(
        _signing_key(),
        _decision_hash(verdict.outcome, verdict.stage, verdict.reason, subject, verdict.score),
    )
    decision = Decision(
        outcome=verdict.outcome,
        stage=verdict.stage,
        reason=verdict.reason,
        subject=subject,
        score=verdict.score,
        signature=f"ecdsa:{signature.hex()}",
    )

    with telemetry.authorization_decision(
        agent_id=agent_id,
        agent_version=agent_version,
        standing=None if verdict.agent is None else verdict.agent.standing,
        action_class=None if proposed is None else proposed.action_class,
        target=None if proposed is None else proposed.target,
        target_tier=None if proposed is None else proposed.target_tier,
        blast_radius=None if proposed is None else proposed.blast_radius,
        reversible=None if proposed is None else proposed.reversible,
        evidence_ids=None if proposed is None else proposed.evidence_refs,
    ) as rec:
        if verdict.score is not None:
            rec.set_risk(
                base=verdict.score.base,
                criticality=verdict.score.criticality,
                blast=verdict.score.blast,
                irreversibility=verdict.score.irreversibility,
                score=verdict.score.score,
            )
        rec.set_outcome(
            outcome=decision.outcome,
            stage=decision.stage,
            reason=decision.reason,
            signature=decision.signature,
        )
    return decision
