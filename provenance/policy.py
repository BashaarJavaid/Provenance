"""The Memory Policy Engine — §2.2's pipeline (items 10 and 12).

The mirror of the gateway: probabilistic recommends, deterministic decides, for beliefs as
for actions (§1.1 property 2). Nothing here reasons. It reads standing, computes a number
from a published formula, compares it to a threshold, signs, and writes — or refuses.

Item 10 shipped this as a stub that could commit exactly one version and refused a second.
Item 12 gave it the versioned store (`beliefs.py`), so a re-affirmation now commits a real
superseding version and `SUPERSESSION_UNSUPPORTED` is gone rather than merely unused. Item 13
wired stage 3 and widened stage 4 to the accumulated evidence set (`docs/adr/ADR-017`). What
runs today:

| §2.2 stage | Here |
|---|---|
| 1. typed-evidence validation | `beliefs.Evidence` is §3.3's seven fields, constructed by code |
| 2. registry read, request-time | `registry.get_agent()`, standing GOOD **and** domain held |
| 3. novelty check | `beliefs.novel()` over `(source_id, observed_at)`; nothing new is a REJECT |
| 4. computed confidence | `confidence()`, §4.3's noisy-OR over the **accumulated** evidence |
| 5. threshold + conflict rule | threshold for every version; §6.3's flip rule is item 14's |
| 6. outcome | COMMIT or REJECT, signed, one `belief.commit` span |

**A status flip is refused, not approximated.** §4.3 puts a flip behind 0.70 *plus* §6.3's
different-source-class rule, and neither exists until item 14. Letting a flip through the
0.50 door in the meantime would mean a single sensor could set and clear its own alarm —
the one thing §6.3 exists to prevent — so a proposal whose status differs from the current
version is answered `REJECT("FLIP_UNSUPPORTED")`. Same status, new evidence, is a
re-affirmation: v2 supersedes v1, and v1 is left exactly as it was committed.

**A version rests on everything it has ever rested on.** §3.2 renders belief #42 citing
`ev-[118,140,141]` where its predecessor #17 cited `ev-[118]`, so a superseding version
carries its predecessor's evidence forward and the confidence recomputes over the union.
Without that, §6.3's legitimate-update case cannot reach the 0.70 door item 14 needs: an
Aug-1 `contractual_record` plus an Aug-15 `third_party_audit` is 0.71 accumulated and 0.55
if only the new item counts. Novelty is what keeps the set honest — it can only ever grow by
observations nobody has made before.

Also still absent by design: the standing-counter write §2.2 stage 6 names (item 14), and
`RETRACT` (§6.4, item 15).

Fail-closed (§7.3): a registry that cannot be read is a REJECT, not a commit; the store's
write is a `create()` so a concurrent one loses rather than clobbers; and every outcome,
including every refusal, lands on a span. `commit()` never raises for a belief it declined
to write — the caller must not be able to swallow a refusal into "nothing happened", the
same reason `gateway.authorize()` returns every terminal outcome as a `Decision`.
"""

from __future__ import annotations

import hashlib
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any, Literal

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from services.gateway import signing

from provenance import beliefs, registry, telemetry
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

# §6.5's decay clock, as one number, and published in §4.3 beside the weights it multiplies.
# §4.3 writes it "half_life_domain"; item 21 is what makes it per-domain, because that is when
# a second domain first writes beliefs. A dict keyed by one key varies by nothing.
HALF_LIFE_DAYS = 30.0

# §6.5's two expiry behaviours. The Sweeper (Phase 9) is what consumes this; item 12 writes
# it so that beliefs committed before the Sweeper exists still carry a decay clock.
ON_EXPIRY = "REVERIFY"

# §4.3: "0.50 for a new belief". The flip threshold (0.70) has no caller until item 14,
# because a flip is refused outright until the rule that governs it exists.
NEW_BELIEF_THRESHOLD = 0.50

# Closed, for the same reason `gateway.DecisionReason` is closed: this lands on a span, and
# §8.1 admits identifiers, enums and numbers but never prose.
CommitReason = Literal[
    "ABOVE_THRESHOLD",
    "BELOW_THRESHOLD",
    "STANDING_NOT_GOOD",
    "DOMAIN_NOT_HELD",
    "REGISTRY_UNAVAILABLE",
    "NO_NEW_EVIDENCE",
    "FLIP_UNSUPPORTED",
    "VERSION_CONFLICT",
    "STORE_UNAVAILABLE",
]


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


def confidence(evidence: Sequence[Evidence], *, now: datetime) -> float:
    """§4.3's noisy-OR: `1 − Π(1 − w_i)` over the **distinct source classes** present.

    Distinctness is what makes corroboration mean something: restating one observation five
    times leaves the product unchanged, so an agent cannot talk a belief over the threshold.
    The strongest (least decayed) item of each class is the one that counts.
    """
    strongest: dict[SourceClass, float] = {}
    for item in evidence:
        age_days = max(0.0, (now - _parse(item.observed_at)).total_seconds() / 86400)
        weight = BASE_WEIGHT[item.source_class] * 2 ** (-age_days / HALF_LIFE_DAYS)
        strongest[item.source_class] = max(strongest.get(item.source_class, 0.0), weight)
    product = 1.0
    for weight in strongest.values():
        product *= 1 - weight
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
    belief_id = f"belief-{entity}"
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
        threshold=NEW_BELIEF_THRESHOLD,
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
) -> _Verdict:
    """§2.2's stages, in order. The earliest refusal wins, and the write happens last.

    Stage 2 runs before the store is touched, which is why a refusal there reports version 1
    and no `supersedes`: an agent whose standing has not been checked does not get a read of
    institutional memory performed on its behalf, and the span's `decision.reason` says
    plainly that the write never reached the store.
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
    # Analyst may have asserted is not a parameter of this function. It is computed over the
    # **accumulated** set (§3.2), so corroboration works across time: an old contractual
    # record and a fresh audit are two distinct source classes even though they arrived a
    # fortnight apart, and `confidence()`'s per-class max is what "re-confirmation raises
    # confidence via decay-reset" means in arithmetic.
    conf = confidence((*known, *new), now=now)
    if conf < NEW_BELIEF_THRESHOLD:
        return _Verdict("REJECT", "BELOW_THRESHOLD", conf, agent, version, supersedes, len(new))

    # Stage 5's conflict rule, as much of it as exists. A flip needs 0.70 and §6.3's
    # different-source-class corroboration; item 14 owns both, and until then the honest
    # answer is a refusal rather than a commit through the new-belief door.
    if previous is not None and previous.status != status:
        return _Verdict("REJECT", "FLIP_UNSUPPORTED", conf, agent, version, supersedes, len(new))

    committed_at = now.astimezone(UTC).strftime(TIMESTAMP)
    proposed = beliefs.BeliefVersion(
        belief_id=belief_id,
        version=version,
        scope="ENTITY",
        domain=domain,
        entity=entity,
        status=status,
        confidence=conf,
        threshold=NEW_BELIEF_THRESHOLD,
        evidence_ids=(*(previous.evidence_ids if previous else ()), *(item.id for item in new)),
        authority=f"{agent.id}@{agent.version} (standing: {agent.standing})",
        committed_at=committed_at,
        committed_by="memory-policy-engine",
        signature=_sign(belief_id, version, "COMMIT", "ABOVE_THRESHOLD", conf).signature,
        supersedes=supersedes,
        half_life_days=HALF_LIFE_DAYS,
        expires_at=(now + timedelta(days=HALF_LIFE_DAYS)).astimezone(UTC).strftime(TIMESTAMP),
        on_expiry=ON_EXPIRY,
    )
    try:
        # Only the novel items are written: the rest are already stored, and `append()` is
        # create-if-absent precisely so re-citing one is a no-op rather than a rewrite.
        await beliefs.append(proposed, new, client=client)
    except beliefs.VersionConflict:
        # Another writer got this version number first. Losing is the correct outcome: §6 is
        # append-only, and the winner's version is the one the chain now runs through.
        return _Verdict("REJECT", "VERSION_CONFLICT", conf, agent, version, supersedes, len(new))
    except beliefs.BeliefStoreError:
        return _Verdict("REJECT", "STORE_UNAVAILABLE", conf, agent, version, supersedes, len(new))
    return _Verdict("COMMIT", "ABOVE_THRESHOLD", conf, agent, version, supersedes, len(new))
