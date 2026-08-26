"""The authorization ledger — what a retraction flags (item 15).

§6.4's third bullet: retraction "flags every action previously authorized on that belief in
the audit log for review." That sentence needs a join, and before this module there was
none. `Action` carries `evidence_refs` (evidence ids, §3.3), `gateway.Decision` carries a
subject and a signature, and neither names a belief. The only belief ids anywhere near an
action are `recall.belief_ids` on the `reasoning.chain` span, which records what memory
*nominated* and is not a durable record of anything.

So this is the durable record: one document per authorized action, citing the beliefs that
informed it.

    authorizations/auth-3f2b1c…  { id, agent_id, action_class, target, outcome, subject,
                                    signature, decided_at, belief_ids: [...], flagged_by: [],
                                    approver }

Three things follow from it that are worth stating before changing anything:

- **`belief_ids` carries what recall resolved by exact key (item 16).** It holds *entity*
  belief ids and only those: §6.2 caps a class belief as advisory, so one may never be what
  an action rested on, and recording one here would make a retraction flag actions on
  grounds §6.2 says they could not have had. `recall.Recalled` keeps the two sets apart and
  `incident.py` cites `entity_ids`, which is what makes that a property of a type rather
  than a rule to remember. The alternative to this collection — flagging by `target ==
  entity` and a time window, with no stored link at all — would flag actions that merely
  touched the same entity, which is a different and weaker claim than the one §6.4 makes.
- **Only *authorized* actions are recorded — and item 30 corrected what that excludes.**
  §6.4 says "previously authorized", so an agent-stage denial and an action still parked on a
  human are both absent: neither happened, and neither rests on a belief in the way that needs
  reviewing. A **human's** verdict is the opposite case and is recorded on both sides. Somebody
  was asked and answered, which is precisely what a ledger is for, and the item's own line
  ("denial is signed into the ledger") asks for it. That is the `approver` field below, and
  `docs/adr/ADR-019` §9 carries the correction.
- **`flag()` is the one `update()` in the memory subsystem, and it is deliberately not in
  `beliefs.py`.** An authorization record is not a belief: §6's append-only rule is about
  what the organization believes, and marking an already-written record for human review
  neither rewrites history nor changes a belief. Keeping it here is what keeps "nothing
  under `provenance/` modifies or deletes a belief version" literally true.

Fail-closed (§7.3), following `registry.py` and `beliefs.py` exactly: no function returns an
optional. An unreachable ledger raises, and `policy.retract()` maps that to a REJECT with no
version written — a retraction whose actions were never flagged is precisely the failure
§6.4 exists to prevent, so it must not look like a success.

Schema reasoning in `docs/adr/ADR-019`.
"""

from __future__ import annotations

import hashlib
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from google.api_core.exceptions import AlreadyExists, GoogleAPIError
from google.cloud import firestore

from provenance.telemetry import AuthOutcome

COLLECTION = "authorizations"

# Matches beliefs.TIMESTAMP and registry.TIMESTAMP: ISO-8601, UTC, `Z` suffix.
TIMESTAMP = "%Y-%m-%dT%H:%M:%SZ"


@dataclass(frozen=True)
class Authorization:
    """One authorized action, and the beliefs it rested on.

    `flagged_by` is the review mark §6.4 asks for: one entry per retraction that reached
    this record, naming the belief and the version that was in force when it was retracted.
    It is a list rather than a flag because one action can rest on several beliefs, and each
    of them can be retracted separately.
    """

    id: str
    agent_id: str
    action_class: str
    target: str
    outcome: AuthOutcome
    subject: str  # "agent@version|action_class|target", as gateway.Decision signed it
    signature: str
    decided_at: str
    belief_ids: tuple[str, ...]
    flagged_by: tuple[dict[str, Any], ...] = ()
    # Empty on every row an agent's own proposal produced, and set only by item 30's resume.
    # `agent_id` stays the proposer either way: the record is about whose action this was, and
    # `approver` is about who answered for it.
    approver: str = ""


class AuditError(Exception):
    """Base for every way the ledger can refuse. Nothing here returns an optional."""


class AuditUnavailable(AuditError):
    """Firestore could not be reached. §7.3: never a silently unrecorded authorization."""


def authorization_id(signature: str) -> str:
    """Content-addressed from the decision signature, the idiom `beliefs.evidence_id()` set.

    `record()` is create-if-absent, so an id that does not determine its own contents would
    let a second write of a colliding id be discarded in silence. A decision signature is
    already unique per decision — it covers the outcome, the stage, the reason, the subject
    and the risk components — so hashing it makes a re-record of the same authorization the
    same document, always.
    """
    return f"auth-{hashlib.sha256(signature.encode()).hexdigest()[:16]}"


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


def to_document(entry: Authorization) -> dict[str, Any]:
    return {
        "id": entry.id,
        "agent_id": entry.agent_id,
        "action_class": entry.action_class,
        "target": entry.target,
        "outcome": entry.outcome,
        "subject": entry.subject,
        "signature": entry.signature,
        "decided_at": entry.decided_at,
        "belief_ids": list(entry.belief_ids),
        "flagged_by": list(entry.flagged_by),
        "approver": entry.approver,
    }


def from_document(doc_id: str, data: dict[str, Any] | None) -> Authorization:
    """Parse one stored record. Raises rather than defaulting on anything malformed."""
    if data is None:
        raise AuditError(f"{COLLECTION}/{doc_id}: document is empty")
    try:
        return Authorization(
            id=data["id"],
            agent_id=data["agent_id"],
            action_class=data["action_class"],
            target=data["target"],
            outcome=data["outcome"],
            subject=data["subject"],
            signature=data["signature"],
            decided_at=data["decided_at"],
            belief_ids=tuple(data["belief_ids"]),
            flagged_by=tuple(data.get("flagged_by", ())),
            approver=data.get("approver", ""),
        )
    except (KeyError, TypeError) as exc:
        raise AuditError(f"{COLLECTION}/{doc_id}: malformed authorization ({exc})") from exc


async def record(
    *,
    agent_id: str,
    action_class: str,
    target: str,
    outcome: AuthOutcome,
    subject: str,
    signature: str,
    belief_ids: Sequence[str],
    now: datetime,
    approver: str = "",
    client: Any | None = None,
) -> Authorization:
    """Write one authorized action to the ledger. Create-if-absent, never a rewrite.

    Re-recording the same decision is a no-op rather than an overwrite — the same posture as
    `beliefs.append()`'s root and evidence writes, and for the same reason: a document that
    has already been flagged must not lose its flag to a replay.
    """
    entry = Authorization(
        id=authorization_id(signature),
        agent_id=agent_id,
        action_class=action_class,
        target=target,
        outcome=outcome,
        subject=subject,
        signature=signature,
        decided_at=now.astimezone(UTC).strftime(TIMESTAMP),
        belief_ids=tuple(belief_ids),
        approver=approver,
    )
    try:
        await _db(client).collection(COLLECTION).document(entry.id).create(to_document(entry))
    except AlreadyExists:
        pass  # This decision is already in the ledger. Its flags are what move.
    except GoogleAPIError as exc:
        raise AuditUnavailable(f"{COLLECTION}/{entry.id}: {exc}") from exc
    return entry


async def flag(belief_id: str, *, version: int, now: datetime, client: Any | None = None) -> int:
    """§6.4's third bullet. Mark every action that rested on this belief, return how many.

    Idempotent: a record already carrying an entry for this `(belief_id, version)` is left
    alone, so re-running a retraction cannot inflate the count or the list. Retracting a
    *later* version of the same belief does append a second entry, which is correct — those
    are two different reviews.
    """
    flagged_at = now.astimezone(UTC).strftime(TIMESTAMP)
    mark = {"belief_id": belief_id, "version": version, "flagged_at": flagged_at}
    try:
        collection = _db(client).collection(COLLECTION)
        query = collection.where(
            filter=firestore.FieldFilter("belief_ids", "array_contains", belief_id)
        )
        count = 0
        async for snapshot in query.stream():
            existing = list(from_document(snapshot.id, snapshot.to_dict()).flagged_by)
            if any(
                entry.get("belief_id") == belief_id and entry.get("version") == version
                for entry in existing
            ):
                continue
            await collection.document(snapshot.id).update({"flagged_by": [*existing, mark]})
            count += 1
    except GoogleAPIError as exc:
        raise AuditUnavailable(f"{COLLECTION}: flagging {belief_id} failed ({exc})") from exc
    return count


async def read(doc_id: str, *, client: Any | None = None) -> Authorization:
    """One stored record by id. Raises if it is absent — there is no optional here either."""
    try:
        snapshot = await _db(client).collection(COLLECTION).document(doc_id).get()
    except GoogleAPIError as exc:
        raise AuditUnavailable(f"{COLLECTION}/{doc_id}: {exc}") from exc
    if not snapshot.exists:
        raise AuditError(f"{COLLECTION}/{doc_id} does not exist")
    return from_document(doc_id, snapshot.to_dict())
