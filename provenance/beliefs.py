"""The versioned belief store and §3.3's typed Evidence (item 12).

Institutional memory is a versioned model of what the organization currently believes, with
full provenance (§6). This module is the *store* half of that and nothing else: it appends
versions, links them, and reads them back. It decides nothing. `policy.py` is the mirror of
the gateway — probabilistic recommends, deterministic decides (§1.1 property 2) — and this
is what the deterministic half writes through, the same way `risk.py` is the table the
gateway scores from.

**Append-only is a property of Firestore here, not of our restraint.** A version document is
written once by `create()` and never touched again — no in-place update, no backlink written
onto a committed version, no delete anywhere in this module. `supersedes` points backwards
only; `superseded_by` is derived on read (version *n* is superseded iff *n+1* exists), so the
chain cannot disagree with itself and a stored link cannot go stale.

Layout, one root document per belief and one immutable document per version:

    beliefs/belief-inventory-api           { belief_id, entity, domain, scope, created_at }
    beliefs/belief-inventory-api/versions/1  { status, confidence, evidence: [ids], ... }
    beliefs/belief-inventory-api/versions/2  { ..., supersedes: 1 }
    evidence/ev-abc123                     { §3.3's seven fields }

Two things follow from it that are worth stating before changing anything:

- **There is no `current_version` pointer.** `current()` walks `versions/1, 2, …` until a
  read misses, so the newest existing version *is* the current one. A pointer would be one
  read instead of two or three, at the cost of a window where a crash between the version
  write and the pointer write leaves a belief no later commit can extend. Versions are the
  only truth; there is nothing to repair.
- **The version document is written last**, after the root document and after every
  `evidence/{id}` it cites. So a crash can leave evidence nothing references yet, which is
  harmless, but never a version whose evidence is missing, which would be a belief citing
  provenance the store cannot produce.

Fail-closed (§7.3), following `registry.py` exactly: no function returns `BeliefVersion |
None`. A missing belief, an unreachable database and a losing concurrent write all raise —
a `None` someone forgets to branch on is how an unwritten belief becomes a written one.

Schema reasoning in `docs/adr/ADR-016`, and `docs/adr/ADR-017` for the novelty check item 13
added over the evidence this module stores (`evidence_id`, `read_evidence`, `novel`). Item 14
adds the §6.3 conflict rule; item 15 `RETRACT`; item 16 recall.
"""

from __future__ import annotations

import hashlib
from collections.abc import Sequence
from dataclasses import asdict, dataclass, replace
from typing import Any

from google.api_core.exceptions import AlreadyExists, GoogleAPIError
from google.cloud import firestore

from provenance.telemetry import BeliefScope, SourceClass

COLLECTION = "beliefs"
EVIDENCE_COLLECTION = "evidence"

# Matches credentials.py and synthetic/company.py: ISO-8601, UTC, `Z` suffix. Public because
# the control loop stamps the Evidence it constructs with the same format.
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
class BeliefVersion:
    """One immutable version of one belief — §3.2's object, as it is stored.

    `evidence_ids` cites `evidence/{id}` documents rather than embedding them, which is what
    lets item 13's novelty check read `(source_id, observed_at)` pairs from one place instead
    of scanning every version's copy.

    `superseded_by` is **derived, never stored**: `to_document()` omits it and the read path
    fills it in. That is what keeps a committed version document write-once.
    """

    belief_id: str
    version: int
    scope: BeliefScope
    domain: str
    entity: str
    status: str
    confidence: float
    threshold: float
    evidence_ids: tuple[str, ...]
    authority: str
    committed_at: str
    committed_by: str
    signature: str
    supersedes: int | None = None
    half_life_days: float = 0.0
    expires_at: str = ""
    on_expiry: str = "REVERIFY"
    superseded_by: int | None = None


class BeliefStoreError(Exception):
    """Base for every way the belief store can refuse. Nothing here returns an optional."""


class BeliefNotFound(BeliefStoreError):
    """No belief with that id, or a root document with no versions under it."""


class BeliefStoreUnavailable(BeliefStoreError):
    """Firestore could not be reached. §7.3: an unwritten belief, never a silently written one."""


class VersionConflict(BeliefStoreError):
    """That version already exists. A concurrent writer won; this one must not overwrite it."""


def payload_hash(payload: object) -> str:
    """`sha256` of what was measured. §3.3 stores the hash; the payload is not authority."""
    return hashlib.sha256(repr(payload).encode()).hexdigest()


def evidence_id(source_id: str, observed_at: str) -> str:
    """§2.2's pair, as the id that names it — content-addressed, not assigned.

    `append()` writes evidence `create()`-if-absent, so an id that does not determine its own
    contents lets the second write of a colliding id be discarded in silence, leaving a
    stored document that disagrees with the pair it claims. Deriving the id from the pair
    makes that unrepresentable: the same observation is the same document, always.
    """
    return f"ev-{hashlib.sha256(f'{source_id}|{observed_at}'.encode()).hexdigest()[:16]}"


def novel(proposed: Sequence[Evidence], known: Sequence[Evidence]) -> tuple[Evidence, ...]:
    """§2.2 stage 3, mechanically: new iff `(source_id, observed_at)` is not already there.

    Pairs, not ids. The id is derived from the pair by `evidence_id()` and would compare the
    same, but a caller that assigns its own — the tests and `verify_belief_store.py` both do
    — must not be able to slip a duplicate past the check by naming it something new. No
    model judgment is involved anywhere in this function, which is the entire point of it.
    """
    seen = {(item.source_id, item.observed_at) for item in known}
    return tuple(item for item in proposed if (item.source_id, item.observed_at) not in seen)


# --- Firestore ------------------------------------------------------------------------------

_client: firestore.AsyncClient | None = None


def _default_client() -> firestore.AsyncClient:
    """The shared connection, built lazily so importing this module needs no credentials."""
    global _client
    if _client is None:
        _client = firestore.AsyncClient()
    return _client


def _db(client: Any | None) -> Any:
    return client if client is not None else _default_client()


def _root(belief_id: str, client: Any | None) -> Any:
    return _db(client).collection(COLLECTION).document(belief_id)


def _version_doc(belief_id: str, version: int, client: Any | None) -> Any:
    return _db(client).collection(f"{COLLECTION}/{belief_id}/versions").document(str(version))


def _evidence_doc(item_id: str, client: Any | None) -> Any:
    return _db(client).collection(EVIDENCE_COLLECTION).document(item_id)


def to_document(version: BeliefVersion) -> dict[str, Any]:
    """The stored payload. `superseded_by` is deliberately absent — it is derived on read."""
    data = asdict(version)
    data.pop("superseded_by")
    data["evidence"] = list(data.pop("evidence_ids"))
    return data


def from_document(belief_id: str, version: int, data: dict[str, Any] | None) -> BeliefVersion:
    """Parse one stored version. Raises rather than defaulting on anything malformed."""
    if data is None:
        raise BeliefStoreError(f"{COLLECTION}/{belief_id}/versions/{version}: document is empty")
    try:
        return BeliefVersion(
            belief_id=data["belief_id"],
            version=data["version"],
            scope=data["scope"],
            domain=data["domain"],
            entity=data["entity"],
            status=data["status"],
            confidence=data["confidence"],
            threshold=data["threshold"],
            evidence_ids=tuple(data["evidence"]),
            authority=data["authority"],
            committed_at=data["committed_at"],
            committed_by=data["committed_by"],
            signature=data["signature"],
            supersedes=data["supersedes"],
            half_life_days=data["half_life_days"],
            expires_at=data["expires_at"],
            on_expiry=data["on_expiry"],
        )
    except (KeyError, TypeError) as exc:
        raise BeliefStoreError(
            f"{COLLECTION}/{belief_id}/versions/{version}: malformed version ({exc})"
        ) from exc


async def _get(document: Any) -> Any:
    try:
        return await document.get()
    except GoogleAPIError as exc:
        raise BeliefStoreUnavailable(str(exc)) from exc


async def history(belief_id: str, *, client: Any | None = None) -> tuple[BeliefVersion, ...]:
    """Every version of one belief, oldest first, with `superseded_by` filled in.

    §6.1: history is retained forever, and this is the read that proves it — a superseded
    version is returned exactly as it was committed, with a link rather than a tombstone.
    """
    if not (await _get(_root(belief_id, client))).exists:
        raise BeliefNotFound(f"{COLLECTION}/{belief_id} does not exist")
    versions: list[BeliefVersion] = []
    version = 1
    while True:
        snapshot = await _get(_version_doc(belief_id, version, client))
        if not snapshot.exists:
            break
        versions.append(from_document(belief_id, version, snapshot.to_dict()))
        version += 1
    if not versions:
        raise BeliefNotFound(f"{COLLECTION}/{belief_id} has no versions")
    return tuple(
        replace(v, superseded_by=v.version + 1 if index + 1 < len(versions) else None)
        for index, v in enumerate(versions)
    )


async def current(belief_id: str, *, client: Any | None = None) -> BeliefVersion:
    """The version in force: the newest one that exists. Raises if the belief does not."""
    return (await history(belief_id, client=client))[-1]


async def read_evidence(ids: Sequence[str], *, client: Any | None = None) -> tuple[Evidence, ...]:
    """Resolve cited ids to the §3.3 objects they name, in the order they were cited.

    A version citing an id no document answers is a belief resting on provenance the store
    cannot produce, so this raises `BeliefNotFound` rather than returning a shorter tuple.
    Silently dropping it would let §2.2's novelty check compare against a history with holes
    in it and call a duplicate new (§7.3).
    """
    items = []
    for item_id in ids:
        snapshot = await _get(_evidence_doc(item_id, client))
        if not snapshot.exists:
            raise BeliefNotFound(f"{EVIDENCE_COLLECTION}/{item_id} is cited but not stored")
        items.append(evidence_from_document(item_id, snapshot.to_dict()))
    return tuple(items)


def evidence_from_document(item_id: str, data: dict[str, Any] | None) -> Evidence:
    """Parse one stored evidence item. Raises rather than defaulting, as `from_document` does."""
    if data is None:
        raise BeliefStoreError(f"{EVIDENCE_COLLECTION}/{item_id}: document is empty")
    try:
        return Evidence(
            id=data["id"],
            source_id=data["source_id"],
            source_class=data["source_class"],
            observed_at=data["observed_at"],
            ingested_at=data["ingested_at"],
            payload_hash=data["payload_hash"],
            verifiable_by=data["verifiable_by"],
        )
    except (KeyError, TypeError) as exc:
        raise BeliefStoreError(
            f"{EVIDENCE_COLLECTION}/{item_id}: malformed evidence ({exc})"
        ) from exc


async def append(
    version: BeliefVersion, evidence: Sequence[Evidence], *, client: Any | None = None
) -> None:
    """Write one new version and the evidence it cites. The only writer in this module.

    Order matters and is the reason there is no transaction: the root document and every
    evidence document are create-if-absent (re-citing an item is a no-op, never a rewrite),
    and the version document is `create()`d last. A losing race raises `VersionConflict`
    rather than clobbering — the same posture as the gateway returning a refusal instead of
    guessing.
    """
    try:
        await _root(version.belief_id, client).create(
            {
                "belief_id": version.belief_id,
                "entity": version.entity,
                "domain": version.domain,
                "scope": version.scope,
                "created_at": version.committed_at,
            }
        )
    except AlreadyExists:
        pass  # A belief this store already knows about. Its versions are what move.
    except GoogleAPIError as exc:
        raise BeliefStoreUnavailable(str(exc)) from exc

    for item in evidence:
        try:
            await _db(client).collection(EVIDENCE_COLLECTION).document(item.id).create(asdict(item))
        except AlreadyExists:
            pass  # The same observation cited by a second version. Stored once (§3.3).
        except GoogleAPIError as exc:
            raise BeliefStoreUnavailable(str(exc)) from exc

    try:
        await _version_doc(version.belief_id, version.version, client).create(to_document(version))
    except AlreadyExists as exc:
        raise VersionConflict(
            f"{COLLECTION}/{version.belief_id}/versions/{version.version} already exists"
        ) from exc
    except GoogleAPIError as exc:
        raise BeliefStoreUnavailable(str(exc)) from exc
