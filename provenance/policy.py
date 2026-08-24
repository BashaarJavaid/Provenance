"""The Memory Policy Engine — §2.2's pipeline, whole (items 10, 12–15).

The mirror of the gateway: probabilistic recommends, deterministic decides, for beliefs as
for actions (§1.1 property 2). Nothing here reasons. It reads standing, computes a number
from a published formula, compares it to a threshold, signs, and writes — or refuses.

Item 10 shipped this as a stub that could commit exactly one version and refused a second.
Item 12 gave it the versioned store (`beliefs.py`), so a re-affirmation now commits a real
superseding version and `SUPERSESSION_UNSUPPORTED` is gone rather than merely unused. Item 13
wired stage 3 and widened stage 4 to the accumulated evidence set (`docs/adr/ADR-017`). Item 14
opened the flip door and wired stage 6's counter (`docs/adr/ADR-018`). Item 15 added §6.4's
retraction as the second public door (`docs/adr/ADR-019`). What runs today:

| §2.2 stage | Here |
|---|---|
| 1. typed-evidence validation | `beliefs.Evidence` is §3.3's seven fields, constructed by code |
| 2. registry read, request-time | `registry.get_agent()`, standing GOOD **and** domain held |
| 3. novelty check | `beliefs.novel()` over `(source_id, observed_at)`; nothing new is a REJECT |
| 4. computed confidence | `confidence()`, §4.3's noisy-OR over the **accumulated** evidence |
| 5. threshold + conflict rule | 0.50 for a new belief, 0.70 **plus** §6.3's class rule for a flip |
| 6. outcome | COMMIT, RETRACT or REJECT, signed, one `belief.commit` span, counter written |

**A status flip is two doors, not one.** §4.3 puts a flip behind 0.70 *and* §6.3 behind at
least one evidence item of a `source_class` different from the class that established the
current status — which is read off the classes the current version's evidence carries. Either
door alone would be weaker than either document: at 0.70 without the class rule, one sensor
could set and clear its own alarm. The two refusals are told apart by name — below the number
is `BELOW_THRESHOLD` carrying `threshold = 0.70`, no different class is `FLIP_UNSUPPORTED` —
because the trace has to say *which* door stopped it. A flip that missed the number while
still clearing 0.50 is named `INSUFFICIENT_FOR_FLIP` instead, because the trace also has to
say *how badly*: that one is an honest agent meeting a higher door and does not cost standing,
where a proposal below both doors is the poisoning case and does. Same status, new evidence, is a
re-affirmation at the 0.50 door: v2 supersedes v1, and v1 is left exactly as it was committed.

**One source class cannot reach 0.70.** The strongest base weight is 0.60 and `confidence()`
collapses a class to its best item, so a flip only ever passes the number by resting on the
accumulated set — which is the case where the class rule is the only thing left standing.

**A version rests on everything it has ever rested on.** §3.2 renders belief #42 citing
`ev-[118,140,141]` where its predecessor #17 cited `ev-[118]`, so a superseding version
carries its predecessor's evidence forward and the confidence recomputes over the union.
Without that, §6.3's legitimate-update case cannot reach the 0.70 door: an Aug-1
`contractual_record` plus an Aug-15 `third_party_audit` is 0.71 accumulated and 0.55 if only
the new item counts. Novelty is what keeps the set honest — it can only ever grow by
observations nobody has made before.

**A retraction is a third door, and §6.4 is the rule for it — not §6.3.** §6.3 hands the
disproven case off explicitly ("*Disproven belief.* Retraction — see §6.4"), so a retraction
does **not** face the different-source-class test. It faces §6.4's own: at least one
disproving item whose `BASE_WEIGHT` is >= the strongest class the version in force rests on.
The number it faces is `NEW_BELIEF_THRESHOLD`, computed over the **disproving evidence
alone** — over the accumulated set any threshold would be free, since that set has already
cleared one. At 0.50 the arithmetic says exactly what §6.4's bullet says: one
`verified_system_observation` (0.60), `third_party_audit` (0.55) or `contractual_record`
(0.50) can retract; `agent_inference` (0.15) and `unverified_external_claim` (0.00) cannot,
and the poisoner fails on both rules rather than one.

**Nothing subtracts.** The `RETRACTED` version cites the accumulated set *plus* the
disproving items, and no class is ever removed from the set a later flip is measured
against — so re-asserting a retracted status is an ordinary flip needing 0.70 and a class
the whole chain does not already carry. This is what ADR-017's and ADR-018's revisit clauses
asked and the answer is that the chain is only ever extended, retraction included.

A rejected write now increments the proposing agent's standing counter — but only the
refusals that are statements about its evidence, see `COUNTED_REJECTIONS`.

Fail-closed (§7.3): a registry that cannot be read is a REJECT, not a commit; the store's
write is a `create()` so a concurrent one loses rather than clobbers; and every outcome,
including every refusal, lands on a span. `commit()` never raises for a belief it declined
to write — the caller must not be able to swallow a refusal into "nothing happened", the
same reason `gateway.authorize()` returns every terminal outcome as a `Decision`. A
retraction flags the audit ledger *before* it appends its version, so a ledger that cannot
be written is a REJECT with no version: a retraction whose actions were never flagged is the
exact failure §6.4 exists to prevent, and it must not look like a success.
"""

from __future__ import annotations

import contextlib
import hashlib
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any, Literal

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from services.gateway import signing

from provenance import audit, beliefs, registry, telemetry
from provenance.beliefs import TIMESTAMP, Evidence
from provenance.telemetry import BeliefOutcome, SourceClass, Standing

# §4.3's published table, verbatim. `unverified_external_claim` is 0.00 — that is the
# poisoning defense as arithmetic rather than as a model's opinion, and it is why a change
# to any number here is a change to §4.3 in the same commit.
BASE_WEIGHT: dict[SourceClass, float] = {
    "verified_system_observation": 0.60,
    "third_party_audit": 0.55,
    "contractual_record": 0.50,
    "agent_inference": 0.15,
    "unverified_external_claim": 0.00,
}

# §6.5's decay clock, published in §4.3 beside the weights it multiplies. §4.3 writes it
# `half_life_domain`, and item 21 is what makes it per-domain -- the item at which a second
# domain first has beliefs of its own to decay. It is a lookup and not a default: a belief in
# a domain with no published half-life must not silently borrow another domain's, so an
# unknown key raises `KeyError`, the same posture `risk.BASE` and `tools.tool_for()` take.
# `tests/test_policy.py` pins the key set against the domains that exist, so a third domain
# cannot ship without one.
#
# Both values are 30 days today, and that is the honest state rather than a placeholder. A
# longer supply-chain half-life is arguable -- a contractual record ages more slowly than a
# live service observation -- but nothing in this project has measured it, and ADR-002's whole
# defence of these numbers is that they are inspectable and fixed rather than tuned. What item
# 21 buys is that the number is now looked up per domain at every place it is used, so a
# future value is one line here and nothing else.
HALF_LIFE_DAYS: dict[str, float] = {
    "infrastructure": 30.0,
    "supply-chain": 30.0,
}

# §6.5's two expiry behaviours. The Sweeper (Phase 9) is what consumes this; item 12 writes
# it so that beliefs committed before the Sweeper exists still carry a decay clock.
ON_EXPIRY = "REVERIFY"

# §4.3: "0.50 for a new belief; 0.70 plus the source-class rule in §6.3 for a status flip".
# Which of the two a proposal is judged against is decided by one thing — whether its status
# differs from the version in force — and the number it faced is stored on the version and
# emitted on the span, so a refusal says which door it was.
# §6.4's retraction faces NEW_BELIEF_THRESHOLD too, but over the disproving evidence alone
# rather than the accumulated set — which is why it is a door at all. See `retract()`.
NEW_BELIEF_THRESHOLD = 0.50
FLIP_THRESHOLD = 0.70

# Closed, for the same reason `gateway.DecisionReason` is closed: this lands on a span, and
# §8.1 admits identifiers, enums and numbers but never prose.
CommitReason = Literal[
    "ABOVE_THRESHOLD",
    "BELOW_THRESHOLD",
    "INSUFFICIENT_FOR_FLIP",
    "STANDING_NOT_GOOD",
    "DOMAIN_NOT_HELD",
    "REGISTRY_UNAVAILABLE",
    "NO_NEW_EVIDENCE",
    "FLIP_UNSUPPORTED",
    "RETRACTION_UNSUPPORTED",
    "NOTHING_TO_RETRACT",
    "VERSION_CONFLICT",
    "STORE_UNAVAILABLE",
]

# §3.2: "domain-typed; UNKNOWN and RETRACTED are universal". `RETRACTED` is the one status
# this module writes by name — every other status is the caller's word for what its domain
# believes. `UNKNOWN` is the second universal one and nothing writes it yet: §6.5's Staleness
# Sweeper is item 29's. It is named here rather than there because item 16's recall has to
# drop it from every read, and a read path that learns about a status only when something
# starts writing it is one release of a stale belief informing a diagnosis (§7.3).
RETRACTED = "RETRACTED"
UNKNOWN = "UNKNOWN"

# §2.2 stage 6 increments the standing counter on a REJECT, and §3.4 narrows which ones:
# "three rejected memory writes **lacking verifiable evidence**". These four are the
# refusals that are statements about the proposing agent's evidence. The rest are not its
# fault — an unreadable registry, an unreadable store and a lost `create()` race are
# infrastructure, and degrading an agent for a Firestore outage would be a bug wearing a
# security guarantee's clothes. STANDING_NOT_GOOD and DOMAIN_NOT_HELD are already-refused
# authority; counting them would only re-degrade an agent that is degraded.
# authority. NOTHING_TO_RETRACT is a statement about the store's state rather than about the
# agent's evidence — retracting a belief that is not there is a mistake, but it is not the
# kind §3.4 counts, and counting it would let a typo degrade an agent. INSUFFICIENT_FOR_FLIP
# is out for the sharper version of the same reason (item 19): the evidence *was* verifiable
# and would have carried a new belief — it met a higher door, which is not a fact about the
# agent's honesty. Counting it would degrade an agent for correctly reporting that its own
# remediation failed. BELOW_THRESHOLD keeps everything below 0.50, which is where the
# unverifiable claims are.
COUNTED_REJECTIONS: frozenset[CommitReason] = frozenset(
    {"BELOW_THRESHOLD", "FLIP_UNSUPPORTED", "RETRACTION_UNSUPPORTED", "NO_NEW_EVIDENCE"}
)


@dataclass(frozen=True)
class BeliefCommit:
    """What the engine decided about one proposed belief, and the signature over it."""

    belief_id: str
    version: int
    outcome: BeliefOutcome
    reason: CommitReason
    confidence: float
    signature: str  # "ecdsa:<hex>", over every field above


class CommitInvalid(Exception):
    """A commit's signature does not verify against the Policy Engine's public key."""


# --- signing ----------------------------------------------------------------------------

# ponytail: per-process signing key, exactly as `gateway._signing_key()` — a belief in the
# store can be checked against `public_key_pem()` from the same run, but not across a Cloud
# Run restart. Upgrade path is the same one: a PEM from Secret Manager, keeping this as the
# credential-free fallback. `THREAT_MODEL.md` states the cost rather than letting "signed"
# imply more than it delivers.
_key: ec.EllipticCurvePrivateKey | None = None


def _signing_key() -> ec.EllipticCurvePrivateKey:
    global _key
    if _key is None:
        _key = signing.generate_private_key()
    return _key


def public_key_pem() -> str:
    """The key every belief committed by this process is signed with, as a PEM string."""
    pem: bytes = signing.public_pem(_signing_key().public_key())
    return pem.decode()


def _commit_hash(belief_id: str, version: int, outcome: str, reason: str, conf: float) -> str:
    return hashlib.sha256(
        f"{belief_id}|{version}|{outcome}|{reason}|{conf:.6f}".encode()
    ).hexdigest()


def _sign(
    belief_id: str, version: int, outcome: BeliefOutcome, reason: CommitReason, conf: float
) -> BeliefCommit:
    signature: bytes = signing.sign(
        _signing_key(), _commit_hash(belief_id, version, outcome, reason, conf)
    )
    return BeliefCommit(
        belief_id=belief_id,
        version=version,
        outcome=outcome,
        reason=reason,
        confidence=conf,
        signature=f"ecdsa:{signature.hex()}",
    )


def verify_commit(commit_: BeliefCommit, public_key_pem_: str) -> None:
    """Raise `CommitInvalid` unless this outcome was signed by that key, unaltered.

    The belief-side twin of `gateway.verify_decision()`, and what makes "every outcome is
    signed and audited" (§2.2 stage 6) a checkable claim rather than a decoration.
    """
    if not commit_.signature.startswith("ecdsa:"):
        raise CommitInvalid("signature: expected an `ecdsa:<hex>` value")
    try:
        raw = bytes.fromhex(commit_.signature.removeprefix("ecdsa:"))
    except ValueError as exc:
        raise CommitInvalid(f"signature: not hex ({exc})") from exc
    public_key = serialization.load_pem_public_key(public_key_pem_.encode())
    if not isinstance(public_key, ec.EllipticCurvePublicKey):
        raise CommitInvalid("public_key: not an EC public key")
    expected = _commit_hash(
        commit_.belief_id, commit_.version, commit_.outcome, commit_.reason, commit_.confidence
    )
    if not signing.verify(public_key, raw, expected):
        raise CommitInvalid(f"signature does not verify for {commit_.belief_id}")


# --- §4.3, the computed number ------------------------------------------------------------


def _parse(timestamp: str) -> datetime:
    return datetime.strptime(timestamp, TIMESTAMP).replace(tzinfo=UTC)


@dataclass(frozen=True)
class Contribution:
    """One source class's term in §4.3's product, with the arithmetic that produced it.

    Item 17's belief inspector renders these rows, and that is the whole reason they are a
    typed object rather than a formatting concern in the route or in the browser. §4.3 is a
    published formula; a second implementation of it — anywhere — is a number that can
    disagree with the one the Policy Engine decided with. `confidence()` is defined in terms
    of this function, so there is exactly one.
    """

    source_class: SourceClass
    base: float
    age_days: float
    weight: float


def contributions(
    evidence: Sequence[Evidence], *, domain: str, now: datetime
) -> tuple[Contribution, ...]:
    """§4.3's per-class weights: `w = base_weight × 2^(-age / half_life_domain)`.

    `domain` selects the half-life (item 21) and is required rather than defaulted, because a
    belief whose domain has no published half-life is a belief nothing can honestly decay.

    One row per **distinct source class**, not one per item — the strongest (least decayed)
    item of each class is the one that counts, which is what makes corroboration mean
    something: restating one observation five times leaves the product unchanged, so an agent
    cannot talk a belief over the threshold. Ordered by descending weight, because that is
    the order the arithmetic reads in.
    """
    half_life = HALF_LIFE_DAYS[domain]
    strongest: dict[SourceClass, Contribution] = {}
    for item in evidence:
        age_days = max(0.0, (now - _parse(item.observed_at)).total_seconds() / 86400)
        base = BASE_WEIGHT[item.source_class]
        row = Contribution(
            source_class=item.source_class,
            base=base,
            age_days=age_days,
            weight=base * 2 ** (-age_days / half_life),
        )
        held = strongest.get(item.source_class)
        if held is None or row.weight > held.weight:
            strongest[item.source_class] = row
    return tuple(sorted(strongest.values(), key=lambda c: -c.weight))


def confidence(evidence: Sequence[Evidence], *, domain: str, now: datetime) -> float:
    """§4.3's noisy-OR: `1 − Π(1 − w_i)` over the **distinct source classes** present."""
    product = 1.0
    for row in contributions(evidence, domain=domain, now=now):
        product *= 1 - row.weight
    return 1 - product


# --- §2.2 ------------------------------------------------------------------------------------


@dataclass(frozen=True)
class _Verdict:
    """The pipeline's result before it is signed and emitted. Internal, mirroring the gateway."""

    outcome: BeliefOutcome
    reason: CommitReason
    confidence: float
    agent: registry.Agent | None = None
    version: int = 1
    supersedes: int | None = None
    # How many of the proposed items survived stage 3. Defaults to zero so a refusal that
    # happened *before* the novelty check reports the count it actually established: none.
    novel_count: int = 0
    # The door this proposal was judged against — 0.70 for a flip, 0.50 otherwise. It reaches
    # both the stored version and the span, so `BELOW_THRESHOLD` says which number it missed.
    threshold: float = NEW_BELIEF_THRESHOLD


async def commit(
    *,
    entity: str,
    domain: str,
    status: str,
    evidence: Sequence[Evidence],
    agent_id: str,
    now: datetime,
    client: Any | None = None,
) -> BeliefCommit:
    """Run §2.2 on one proposed belief. Returns a signed outcome; a REJECT is not an error."""
    belief_id = beliefs.belief_id_for(entity)
    verdict = await _decide(
        belief_id=belief_id,
        entity=entity,
        domain=domain,
        status=status,
        evidence=evidence,
        agent_id=agent_id,
        now=now,
        client=client,
    )
    return await _finish(
        verdict,
        belief_id=belief_id,
        entity=entity,
        domain=domain,
        status=status,
        evidence=evidence,
        agent_id=agent_id,
        now=now,
        client=client,
    )


async def retract(
    *,
    entity: str,
    domain: str,
    evidence: Sequence[Evidence],
    agent_id: str,
    now: datetime,
    client: Any | None = None,
) -> BeliefCommit:
    """§6.4: retract a belief that turned out to be wrong. The second door, not a status.

    There is no `status` parameter because there is no choice to make — a retraction writes
    `RETRACTED` (§3.2: "UNKNOWN and RETRACTED are universal"). What the caller supplies is
    the *disproving* evidence, and §6.4's gate is a statement about it: at least one item
    whose source class is at least as strong as the strongest class the version in force
    rests on. §6.3's different-class rule does not apply — §6.3 hands this case to §6.4.

    Every stage before that is shared with `commit()` verbatim, novelty included: a belief
    cannot be retracted by re-citing the evidence that established it.

    Returns a signed outcome; a REJECT is not an error, exactly as `commit()`'s is not.
    """
    belief_id = beliefs.belief_id_for(entity)
    verdict = await _decide(
        belief_id=belief_id,
        entity=entity,
        domain=domain,
        status=RETRACTED,
        evidence=evidence,
        agent_id=agent_id,
        now=now,
        client=client,
        retracting=True,
    )
    return await _finish(
        verdict,
        belief_id=belief_id,
        entity=entity,
        domain=domain,
        status=RETRACTED,
        evidence=evidence,
        agent_id=agent_id,
        now=now,
        client=client,
    )


async def _finish(
    verdict: _Verdict,
    *,
    belief_id: str,
    entity: str,
    domain: str,
    status: str,
    evidence: Sequence[Evidence],
    agent_id: str,
    now: datetime,
    client: Any | None,
) -> BeliefCommit:
    """§2.2 stage 6, shared by both doors: the counter, the signature and the one span."""
    # The half that is not the span: a rejection whose cause is the agent's own
    # evidence increments its standing counter, and the third inside §3.4's window degrades it.
    if verdict.agent is not None and verdict.reason in COUNTED_REJECTIONS:
        # ponytail: best-effort. Nothing was committed either way, so a registry that cannot be
        # written costs a missed increment, not a wrong answer — and raising here would turn a
        # correct refusal into an exception out of the incident's resolve node.
        with contextlib.suppress(registry.RegistryError):
            await registry.record_rejection(verdict.agent, verdict.reason, now=now, client=client)

    signed = _sign(belief_id, verdict.version, verdict.outcome, verdict.reason, verdict.confidence)

    with telemetry.belief_commit(
        agent_id=agent_id,
        agent_version="unknown" if verdict.agent is None else verdict.agent.version,
        standing=_standing(verdict.agent),
        belief_id=belief_id,
        belief_version=verdict.version,
        scope="ENTITY",
        domain=domain,
        entity=entity,
        status=status,
        confidence=verdict.confidence,
        threshold=verdict.threshold,
        evidence_ids=[item.id for item in evidence],
        source_classes=[item.source_class for item in evidence],
        # What survived stage 3, while `evidence_ids` and `source_classes` above stay as
        # proposed. The gap between them is the audit trail: a re-affirmation that cited three
        # items and moved on one says so, and a refusal says `novel_count = 0`.
        novel_count=verdict.novel_count,
        # Present whenever a predecessor was found — on the refusal to flip one as much as on
        # the version that supersedes it. Omitted entirely for a first belief.
        supersedes=verdict.supersedes,
    ) as rec:
        rec.set_outcome(outcome=signed.outcome, reason=signed.reason, signature=signed.signature)
    return signed


def _standing(agent: registry.Agent | None) -> Standing:
    """An unreadable registry reports the standing a fail-closed engine acted on, not a blank.

    The span's `agent.standing` is required by §8.1, and "we could not read it" and "we read
    GOOD" must not look alike. SUSPENDED is what this write was in fact treated as.
    """
    return "SUSPENDED" if agent is None else agent.standing


def _strength(evidence: Sequence[Evidence]) -> float:
    """The strongest source class present, by §4.3's published base weight. Zero if empty."""
    return max((BASE_WEIGHT[item.source_class] for item in evidence), default=0.0)


async def _decide(
    *,
    belief_id: str,
    entity: str,
    domain: str,
    status: str,
    evidence: Sequence[Evidence],
    agent_id: str,
    now: datetime,
    client: Any | None,
    retracting: bool = False,
) -> _Verdict:
    """§2.2's stages, in order. The earliest refusal wins, and the write happens last.

    Stage 2 runs before the store is touched, which is why a refusal there reports version 1
    and no `supersedes`: an agent whose standing has not been checked does not get a read of
    institutional memory performed on its behalf, and the span's `decision.reason` says
    plainly that the write never reached the store.

    `retracting` swaps §6.4's gate in for §6.3's at stages 4 and 5 and nothing else — stages
    2 and 3 are identical for both doors, which is the point of one pipeline rather than two.
    """
    # Stage 2 — the registry, read at request time (§1.1 property 4). A DEGRADED agent's
    # memory writes are rejected outright (§3.4); an unreadable registry is the same answer,
    # because an authority check that did not happen is not one that passed (§7.3).
    try:
        agent = await registry.get_agent(agent_id, client=client)
    except registry.RegistryError:
        return _Verdict("REJECT", "REGISTRY_UNAVAILABLE", 0.0)
    if agent.standing != "GOOD":
        return _Verdict("REJECT", "STANDING_NOT_GOOD", 0.0, agent)
    if domain not in agent.memory_domains:
        return _Verdict("REJECT", "DOMAIN_NOT_HELD", 0.0, agent)

    # The version at stake. A belief with no history is v1; one with a v1 in force is v2, and
    # `current()` raising rather than returning `None` is what keeps "the store was
    # unreadable" from being mistaken for "there is nothing here" (§7.3).
    try:
        previous: beliefs.BeliefVersion | None = await beliefs.current(belief_id, client=client)
    except beliefs.BeliefNotFound:
        previous = None
    except beliefs.BeliefStoreError:
        return _Verdict("REJECT", "STORE_UNAVAILABLE", 0.0, agent)
    version = 1 if previous is None else previous.version + 1
    supersedes = None if previous is None else previous.version

    # §6.4 retracts "a belief committed in good faith that turns out to be wrong", so there
    # has to be one. An absent belief and an already-retracted one are the same answer: there
    # is nothing here to withdraw. Not counted against the agent — this is a statement about
    # the store's state, not about the evidence it brought (§3.4).
    if retracting and (previous is None or previous.status == RETRACTED):
        return _Verdict("REJECT", "NOTHING_TO_RETRACT", 0.0, agent, version, supersedes)

    # Stage 3 — §2.2's novelty check, mechanical. It compares `(source_id, observed_at)`
    # against what this belief already rests on, and nothing here reasons about the evidence
    # or its plausibility. An id no document answers raises rather than reading as absent:
    # a history with holes in it would call a duplicate new (§7.3).
    known: tuple[Evidence, ...] = ()
    if previous is not None:
        try:
            known = await beliefs.read_evidence(previous.evidence_ids, client=client)
        except beliefs.BeliefStoreError:
            return _Verdict("REJECT", "STORE_UNAVAILABLE", 0.0, agent, version, supersedes)
    new = beliefs.novel(evidence, known)

    # §6.3: "the claim must carry evidence that is **new**". A first belief has no history to
    # be novel against, so this can only ever refuse a proposal that adds nothing to one that
    # already exists — re-running the same observation is not a second reason to believe it.
    if previous is not None and not new:
        return _Verdict("REJECT", "NO_NEW_EVIDENCE", 0.0, agent, version, supersedes)

    # Stage 4 — the number is computed here and nowhere else (§4.1, §4.4). Whatever the
    # Analyst may have asserted is not a parameter of this function. For a commit it is
    # computed over the **accumulated** set (§3.2), so corroboration works across time: an old
    # contractual record and a fresh audit are two distinct source classes even though they
    # arrived a fortnight apart, and `confidence()`'s per-class max is what "re-confirmation
    # raises confidence via decay-reset" means in arithmetic.
    #
    # A retraction is measured over the **disproving items alone**, and that is what makes its
    # door a door: over the accumulated set any threshold is free, since that set has already
    # cleared one. What §6.4 asks is how strong the case *against* the belief is.
    conf = confidence(new if retracting else (*known, *new), domain=domain, now=now)

    # Stage 5 — §4.3's thresholds and the conflict rule for whichever door this is. Which one
    # a proposal faces is decided by facts, not judgment: a retraction faces §6.4, a claimed
    # status differing from the one in force faces §6.3, and a first belief has nothing to
    # contradict so it is never a flip.
    flip = not retracting and previous is not None and previous.status != status
    threshold = FLIP_THRESHOLD if flip else NEW_BELIEF_THRESHOLD
    if conf < threshold:
        # Two different statements about the proposing agent, and §3.4's counter needs them
        # apart. "Your evidence could not support a belief at all" is the poisoning case --
        # `unverified_external_claim` at 0.00 -- and it must cost standing. "Your evidence was
        # good enough for a new belief and not for overturning one" is an honest agent meeting
        # a higher door, and counting it would degrade an agent for reporting accurately: item
        # 19's refuted remediation brings a real `verified_system_observation` at 0.60 against
        # the 0.70 flip door. The split lands exactly on `NEW_BELIEF_THRESHOLD`, so the
        # poisoner is below both doors and still reported under the counted reason.
        reason: CommitReason = (
            "INSUFFICIENT_FOR_FLIP" if flip and conf >= NEW_BELIEF_THRESHOLD else "BELOW_THRESHOLD"
        )
        return _Verdict("REJECT", reason, conf, agent, version, supersedes, len(new), threshold)

    # §6.3: a flip "additionally requires at least one evidence item of a `source_class`
    # different from the class that established the current status" — which is the set of
    # classes the version in force rests on, already in hand from stage 3's read. A single
    # sensor cannot both set and clear an alarm, and this is that sentence as a set difference.
    if flip and not {item.source_class for item in new} - {item.source_class for item in known}:
        return _Verdict(
            "REJECT", "FLIP_UNSUPPORTED", conf, agent, version, supersedes, len(new), threshold
        )

    # §6.4: a retraction "requires evidence of a source class **at least as strong** as the
    # class that established the belief". The baseline is the strongest class the version in
    # force rests on — its accumulated set, the same reading item 14 gave §6.3's near-identical
    # phrase, and free because stage 3 already resolved it. Published `BASE_WEIGHT`, not the
    # decayed weight: §6.4 compares classes, and a rule that changed answer with the clock
    # would let a belief become unretractable by nothing but sitting there.
    if retracting and _strength(new) < _strength(known):
        return _Verdict(
            "REJECT",
            "RETRACTION_UNSUPPORTED",
            conf,
            agent,
            version,
            supersedes,
            len(new),
            threshold,
        )

    # §6.4's third bullet, and it happens **before** the version is appended. `beliefs.append()`
    # orders its writes on the same principle: a flag pointing at a retraction that never
    # landed is a false alarm a human reviews and dismisses, while a retraction whose actions
    # were never flagged is a decision resting on a wrong thing that nobody knows about — the
    # exact failure §6.4 exists to prevent. So the flag goes first and its failure is a REJECT.
    if retracting:
        assert previous is not None  # the NOTHING_TO_RETRACT guard above routes here only if so
        try:
            await audit.flag(belief_id, version=previous.version, now=now, client=client)
        except audit.AuditError:
            return _Verdict(
                "REJECT", "STORE_UNAVAILABLE", conf, agent, version, supersedes, len(new), threshold
            )

    committed_at = now.astimezone(UTC).strftime(TIMESTAMP)
    outcome: BeliefOutcome = "RETRACT" if retracting else "COMMIT"
    proposed = beliefs.BeliefVersion(
        belief_id=belief_id,
        version=version,
        scope="ENTITY",
        domain=domain,
        entity=entity,
        status=status,
        confidence=conf,
        threshold=threshold,
        evidence_ids=(*(previous.evidence_ids if previous else ()), *(item.id for item in new)),
        authority=f"{agent.id}@{agent.version} (standing: {agent.standing})",
        committed_at=committed_at,
        committed_by="memory-policy-engine",
        signature=_sign(belief_id, version, outcome, "ABOVE_THRESHOLD", conf).signature,
        supersedes=supersedes,
        half_life_days=HALF_LIFE_DAYS[domain],
        expires_at=(now + timedelta(days=HALF_LIFE_DAYS[domain]))
        .astimezone(UTC)
        .strftime(TIMESTAMP),
        on_expiry=ON_EXPIRY,
    )
    try:
        # Only the novel items are written: the rest are already stored, and `append()` is
        # create-if-absent precisely so re-citing one is a no-op rather than a rewrite.
        await beliefs.append(proposed, new, client=client)
    except beliefs.VersionConflict:
        # Another writer got this version number first. Losing is the correct outcome: §6 is
        # append-only, and the winner's version is the one the chain now runs through.
        return _Verdict(
            "REJECT", "VERSION_CONFLICT", conf, agent, version, supersedes, len(new), threshold
        )
    except beliefs.BeliefStoreError:
        return _Verdict(
            "REJECT", "STORE_UNAVAILABLE", conf, agent, version, supersedes, len(new), threshold
        )
    return _Verdict(
        outcome, "ABOVE_THRESHOLD", conf, agent, version, supersedes, len(new), threshold
    )
