"""The Memory Policy Engine — a stub of §2.2, enough to commit the first belief (item 10).

The mirror of the gateway: probabilistic recommends, deterministic decides, for beliefs as
for actions (§1.1 property 2). Nothing here reasons. It reads standing, computes a number
from a published formula, compares it to a threshold, signs, and writes — or refuses.

**A stub, and the stub is the point.** Phase 4 owns the full engine (items 12–14); item 10
owns exactly the stages that item 5 and §4.3 already make free, so that incident #1 ends in
a belief rather than in an unwritten intention. What is here:

| §2.2 stage | Here |
|---|---|
| 1. typed-evidence validation | `Evidence` is §3.3's seven fields, constructed by code |
| 2. registry read, request-time | `registry.get_agent()`, standing GOOD **and** domain held |
| 3. novelty check | **absent** — a first belief has no history to be novel against |
| 4. computed confidence | `confidence()`, §4.3's noisy-OR (item 13 owns the full version) |
| 5. threshold + conflict rule | threshold only — a first belief is not a flip (§6.3) |
| 6. outcome | COMMIT or REJECT, signed, one `belief.commit` span |

And what is deliberately not: supersession and RETRACT (§6.4), an `evidence/{id}` collection,
the §6.3 conflict rule, and the standing-counter write §2.2 stage 6 names. A second version
of a belief is therefore not something this module can produce — it `REJECT`s with
`SUPERSESSION_UNSUPPORTED` rather than overwriting v1 or writing an unlinked v2. Committing
a belief the store cannot then trace back to its predecessor is worse than not committing.

Fail-closed (§7.3): a registry that cannot be read is a REJECT, not a commit; the write is a
`create()` so a concurrent one loses rather than clobbers; and every outcome, including every
refusal, lands on a span. `commit()` never raises for a belief it declined to write — the
caller must not be able to swallow a refusal into "nothing happened", the same reason
`gateway.authorize()` returns every terminal outcome as a `Decision`.
"""

from __future__ import annotations

import hashlib
from collections.abc import Sequence
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from typing import Any, Literal

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from google.api_core.exceptions import AlreadyExists, GoogleAPIError
from google.cloud import firestore
from services.gateway import signing

from provenance import registry, telemetry
from provenance.telemetry import BeliefOutcome, SourceClass, Standing

COLLECTION = "beliefs"

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

# §6.5's decay clock, as one number. Item 13 makes it per-domain ("half_life_domain"); with
# one domain writing beliefs there is nothing yet to vary it by.
HALF_LIFE_DAYS = 30.0

# §4.3: "0.50 for a new belief". The flip threshold (0.70) has no caller until item 14,
# because a flip needs a belief to flip.
NEW_BELIEF_THRESHOLD = 0.50

# Closed, for the same reason `gateway.DecisionReason` is closed: this lands on a span, and
# §8.1 admits identifiers, enums and numbers but never prose.
CommitReason = Literal[
    "ABOVE_THRESHOLD",
    "BELOW_THRESHOLD",
    "STANDING_NOT_GOOD",
    "DOMAIN_NOT_HELD",
    "REGISTRY_UNAVAILABLE",
    "SUPERSESSION_UNSUPPORTED",
    "STORE_UNAVAILABLE",
]

# Matches credentials.py and synthetic/company.py: ISO-8601, UTC, `Z` suffix. Public because
# item 10's control loop stamps the Evidence it constructs with the same format.
TIMESTAMP = "%Y-%m-%dT%H:%M:%SZ"


@dataclass(frozen=True)
class Evidence:
    """§3.3's seven fields. Constructed by code from something code measured, never by a model.

    `verifiable_by` is the field that makes the rest checkable: it names how a third party
    would re-derive this item. For incident #1 that is a re-read of `services/inventory-api`,
    which is exactly the read the executor performed.
    """

    id: str
    source_id: str
    source_class: SourceClass
    observed_at: str
    ingested_at: str
    payload_hash: str
    verifiable_by: str


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


def payload_hash(payload: object) -> str:
    """`sha256` of what was measured. §3.3 stores the hash; the payload is not authority."""
    return hashlib.sha256(repr(payload).encode()).hexdigest()


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


# --- the store -----------------------------------------------------------------------------

_store: firestore.AsyncClient | None = None


def _default_client() -> firestore.AsyncClient:
    """The shared connection, built lazily so importing this module needs no credentials."""
    global _store
    if _store is None:
        _store = firestore.AsyncClient()
    return _store


def _document(belief_id: str, client: Any | None) -> Any:
    return (
        (client if client is not None else _default_client())
        .collection(COLLECTION)
        .document(belief_id)
    )


# --- §2.2 ------------------------------------------------------------------------------------


@dataclass(frozen=True)
class _Verdict:
    """The pipeline's result before it is signed and emitted. Internal, mirroring the gateway."""

    outcome: BeliefOutcome
    reason: CommitReason
    confidence: float
    agent: registry.Agent | None = None


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
    version = 1  # A first belief. The version that follows one is item 14's.
    belief_id = f"belief-{entity}-{version}"
    verdict = await _decide(
        belief_id=belief_id,
        version=version,
        entity=entity,
        domain=domain,
        status=status,
        evidence=evidence,
        agent_id=agent_id,
        now=now,
        client=client,
    )
    signed = _sign(belief_id, version, verdict.outcome, verdict.reason, verdict.confidence)

    with telemetry.belief_commit(
        agent_id=agent_id,
        agent_version="unknown" if verdict.agent is None else verdict.agent.version,
        standing=_standing(verdict.agent),
        belief_id=belief_id,
        belief_version=version,
        scope="ENTITY",
        domain=domain,
        entity=entity,
        status=status,
        confidence=verdict.confidence,
        threshold=NEW_BELIEF_THRESHOLD,
        evidence_ids=[item.id for item in evidence],
        source_classes=[item.source_class for item in evidence],
        # Every item of a first belief is novel: there is no history for it not to be new
        # against. The mechanical `(source_id, observed_at)` check is item 13's.
        novel_count=len(evidence),
        # No `supersedes`: this module cannot produce a version that follows one.
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
    version: int,
    entity: str,
    domain: str,
    status: str,
    evidence: Sequence[Evidence],
    agent_id: str,
    now: datetime,
    client: Any | None,
) -> _Verdict:
    """§2.2's stages. The earliest refusal wins, and the write is the last thing that happens."""
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

    # Stage 4 — the number is computed here and nowhere else (§4.1, §4.4). Whatever the
    # Analyst may have asserted is not a parameter of this function.
    conf = confidence(evidence, now=now)
    if conf < NEW_BELIEF_THRESHOLD:
        return _Verdict("REJECT", "BELOW_THRESHOLD", conf, agent)

    document = {
        "id": belief_id,
        "version": version,
        "scope": "ENTITY",
        "domain": domain,
        "entity": entity,
        "status": status,
        "confidence": conf,
        "threshold": NEW_BELIEF_THRESHOLD,
        "evidence": [asdict(item) for item in evidence],
        "authority": f"{agent.id}@{agent.version} (standing: {agent.standing})",
        "committed_at": now.astimezone(UTC).strftime(TIMESTAMP),
        "committed_by": "memory-policy-engine",
        "signature": _sign(belief_id, version, "COMMIT", "ABOVE_THRESHOLD", conf).signature,
    }
    try:
        # `create`, not `set`: §6 makes beliefs append-only, and this module cannot write the
        # supersession link a v2 would need. Losing the race is the correct outcome.
        await _document(belief_id, client).create(document)
    except AlreadyExists:
        return _Verdict("REJECT", "SUPERSESSION_UNSUPPORTED", conf, agent)
    except GoogleAPIError:
        return _Verdict("REJECT", "STORE_UNAVAILABLE", conf, agent)
    return _Verdict("COMMIT", "ABOVE_THRESHOLD", conf, agent)
