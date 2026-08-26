"""The approval queue — where a held incident waits for a human (item 30).

§2.1 stage 7: "a held action parks the incident; the approval card lands in the store
operations manager's queue; the incident resumes on approve/deny." Before this module a
`HOLD` was a dead end — `incident.py` routed to `halt()`, the run returned `outcome=HELD`,
and nothing was written anywhere, because §6.4's ledger records only what was *authorized*.
So a held action existed in the trace for as long as the process lived and nowhere else.

    approvals/appr-3f2b1c…  { id, incident_id, state, proposal, subject, held_signature,
                              entity_ids: [...], domain, routed_to, trigger_target,
                              trigger_signal, trigger_observed_value, trace_id, parked_at,
                              resolved_at, approver }

This module is a **record, not a decision**. `gateway.resolve()` owns the verdict and
`incident.resume()` owns the loop; nothing here consults the risk table, reads the registry
or judges anything. It is `audit.py`'s shape — content-addressed ids, create-if-absent,
fail-closed, no function returning an optional — for the same reason: a queue entry that
can go missing quietly is a held action nobody will ever answer.

Four things follow from it that are worth stating before changing anything:

- **`proposal` is the raw dict the Planner emitted, not a validated `Action`.** A resume
  re-validates and re-scores it from scratch (`gateway.resolve()`), so what is stored here
  is an input to that pipeline rather than a conclusion anybody may act on. `subject` and
  `held_signature` are carried as *provenance* — the gateway's signing key is generated per
  process (`gateway._signing_key()`), so a park that outlives its process cannot have its
  own signature checked, and the design does not ask it to. Reasoning in `ADR-032` §3.
- **Nothing expires.** §7.3's row is "Human approver unavailable → held actions stay parked;
  nothing auto-approves on timeout", and that is the whole rule: no TTL field, no expiry
  branch, no Sweeper involvement. `tests/test_approvals.py` asserts a park left alone is
  still `PARKED`, so the absence is checked rather than merely true today.
- **`resolve()` is the one `update()` here, and it only ever runs `PARKED → APPROVED |
  DENIED`.** A record already resolved refuses — the same refusal `policy.expire()` makes
  against an already-`UNKNOWN` belief, and for the same reason: without it a replayed POST
  executes the action a second time.
- **`entity_ids` is carried so the ledger row written at resume can cite it.** §6.4's
  retraction join has to survive a park: the beliefs that informed the proposal were
  recalled minutes or days before the human answered, and re-running recall at resume would
  cite a different set than the one the fleet actually reasoned from. Entity ids only —
  §6.2 caps a class belief as advisory, and `recall.Recalled.entity_ids` is what keeps that
  a property of a type rather than a rule to remember.

Schema and design reasoning in `docs/adr/ADR-032`.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, Literal

from google.api_core.exceptions import AlreadyExists, GoogleAPIError
from google.cloud import firestore

COLLECTION = "approvals"

# Matches audit.TIMESTAMP, beliefs.TIMESTAMP and registry.TIMESTAMP: ISO-8601, UTC, `Z`.
TIMESTAMP = "%Y-%m-%dT%H:%M:%SZ"

ApprovalState = Literal["PARKED", "APPROVED", "DENIED"]

# The two states a park may move to, and nothing else. `PARKED` is absent on purpose: a
# resolution never returns a record to the queue.
_RESOLVED_STATES: tuple[ApprovalState, ...] = ("APPROVED", "DENIED")

# An approver id lands on a span, and §8.1 admits "identifiers, hashes, enums and numbers
# only — never content". A bounded identifier is what that means here: this is the trust
# boundary between an HTTP body and the trace, so the check is at the door rather than at
# the exporter. Deliberately not an allowlist — §9 names Dana Ruiz as a persona and nothing
# in the design reads a human record, so a roster of permitted humans would be a rule
# invented here rather than one any document makes (`ADR-032` §5).
APPROVER_MAX_LENGTH = 64
_APPROVER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._@+-]*$")


class ApprovalError(Exception):
    """Base for every way the queue can refuse. Nothing here returns an optional."""


class ApprovalUnavailable(ApprovalError):
    """Firestore could not be reached. §7.3: never a silently unrecorded hold."""


class ApprovalNotFound(ApprovalError):
    """No such parked approval. Distinct from unavailable: one is absence, one is failure."""


class ApprovalNotPending(ApprovalError):
    """This approval has already been answered. A verdict is given exactly once."""


@dataclass(frozen=True)
class Approval:
    """One held action waiting on a human, and everything a resume needs to act on it."""

    id: str
    incident_id: str
    state: ApprovalState
    proposal: dict[str, Any]  # the raw emission, re-validated at resume — never trusted
    subject: str  # "agent@version|action_class|target", as gateway.Decision signed it
    held_signature: str  # the HOLD's signature, as provenance only (see the module docstring)
    entity_ids: tuple[str, ...]
    # Which domain reasoned about this, and which agent it was. Stored rather than re-derived
    # at resume for `entity_ids`' reason: a resume must act on what the fleet actually did, and
    # `incident.DOMAINS` is keyed on a classification the Orchestrator made at trigger time.
    # They are what the committed belief's domain and `committed_by` are read from.
    domain: str
    routed_to: str
    # The three wake-on-event facts: two open `telemetry.incident()`'s root span, and the
    # measured value is what §5.8's Verification Agent judges the post-state against. The
    # resumed leg is the same incident and says what woke the fleet rather than re-describing
    # itself as something a human started. `raw_content` is deliberately **not** here: it is
    # untrusted content, item 26 reduced it to a fact before the incident began, and storing it
    # would put the payload back in the store §8.1 keeps it out of.
    trigger_target: str
    trigger_signal: str
    trigger_observed_value: float
    trace_id: str  # the trace the park happened in; the resumed leg opens its own
    parked_at: str
    resolved_at: str = ""
    approver: str = ""


def approval_id(signature: str) -> str:
    """Content-addressed from the HOLD's signature, the idiom `audit.authorization_id()` set.

    `park()` is create-if-absent, so an id that did not determine its own contents would let
    a second write of a colliding id be discarded in silence. A decision signature already
    covers the outcome, stage, reason, subject and risk components, so re-running the same
    held incident parks the same document rather than a second queue entry for one action.
    """
    return f"appr-{hashlib.sha256(signature.encode()).hexdigest()[:16]}"


def check_approver(approver: str) -> str:
    """Raise unless this is a bounded identifier. The one validation at the HTTP boundary."""
    if not approver or len(approver) > APPROVER_MAX_LENGTH or not _APPROVER.match(approver):
        raise ApprovalError(
            f"approver: expected 1-{APPROVER_MAX_LENGTH} identifier characters, got {approver!r}"
        )
    return approver


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


def to_document(record: Approval) -> dict[str, Any]:
    return {
        "id": record.id,
        "incident_id": record.incident_id,
        "state": record.state,
        "proposal": dict(record.proposal),
        "subject": record.subject,
        "held_signature": record.held_signature,
        "entity_ids": list(record.entity_ids),
        "domain": record.domain,
        "routed_to": record.routed_to,
        "trigger_target": record.trigger_target,
        "trigger_signal": record.trigger_signal,
        "trigger_observed_value": record.trigger_observed_value,
        "trace_id": record.trace_id,
        "parked_at": record.parked_at,
        "resolved_at": record.resolved_at,
        "approver": record.approver,
    }


def from_document(doc_id: str, data: dict[str, Any] | None) -> Approval:
    """Parse one stored record. Raises rather than defaulting on anything malformed."""
    if data is None:
        raise ApprovalError(f"{COLLECTION}/{doc_id}: document is empty")
    try:
        return Approval(
            id=data["id"],
            incident_id=data["incident_id"],
            state=data["state"],
            proposal=dict(data["proposal"]),
            subject=data["subject"],
            held_signature=data["held_signature"],
            entity_ids=tuple(data["entity_ids"]),
            domain=data["domain"],
            routed_to=data["routed_to"],
            trigger_target=data["trigger_target"],
            trigger_signal=data["trigger_signal"],
            trigger_observed_value=float(data["trigger_observed_value"]),
            trace_id=data["trace_id"],
            parked_at=data["parked_at"],
            resolved_at=data.get("resolved_at", ""),
            approver=data.get("approver", ""),
        )
    except (KeyError, TypeError) as exc:
        raise ApprovalError(f"{COLLECTION}/{doc_id}: malformed approval ({exc})") from exc


async def park(
    *,
    incident_id: str,
    proposal: dict[str, Any],
    subject: str,
    held_signature: str,
    entity_ids: tuple[str, ...],
    domain: str,
    routed_to: str,
    trigger_target: str,
    trigger_signal: str,
    trigger_observed_value: float,
    trace_id: str,
    now: datetime,
    client: Any | None = None,
) -> Approval:
    """Put one held action in the queue. Create-if-absent, never a rewrite.

    Re-parking the same decision is a no-op rather than an overwrite, the posture
    `audit.record()` and `beliefs.append()` already take: a record somebody has since
    answered must not be returned to `PARKED` by a replay.
    """
    record = Approval(
        id=approval_id(held_signature),
        incident_id=incident_id,
        state="PARKED",
        proposal=proposal,
        subject=subject,
        held_signature=held_signature,
        entity_ids=entity_ids,
        domain=domain,
        routed_to=routed_to,
        trigger_target=trigger_target,
        trigger_signal=trigger_signal,
        trigger_observed_value=trigger_observed_value,
        trace_id=trace_id,
        parked_at=now.astimezone(UTC).strftime(TIMESTAMP),
    )
    try:
        await _db(client).collection(COLLECTION).document(record.id).create(to_document(record))
    except AlreadyExists:
        return await get(record.id, client=client)
    except GoogleAPIError as exc:
        raise ApprovalUnavailable(f"{COLLECTION}/{record.id}: {exc}") from exc
    return record


async def get(approval_id_: str, *, client: Any | None = None) -> Approval:
    """One record by id. Raises on absence — the caller has an id it got from somewhere."""
    try:
        snapshot = await _db(client).collection(COLLECTION).document(approval_id_).get()
    except GoogleAPIError as exc:
        raise ApprovalUnavailable(f"{COLLECTION}/{approval_id_}: {exc}") from exc
    if not snapshot.exists:
        raise ApprovalNotFound(f"{COLLECTION}/{approval_id_} does not exist")
    return from_document(approval_id_, snapshot.to_dict())


async def pending(*, client: Any | None = None) -> list[Approval]:
    """Every parked approval, oldest first — what `GET /approvals` serves.

    Filtered server-side on `state`, which needs no composite index: a single-field equality
    is covered by Firestore's automatic indexes. Ordering is done here rather than in the
    query for the same reason — an `order_by` on a second field would need one.
    """
    try:
        query = (
            _db(client)
            .collection(COLLECTION)
            .where(filter=firestore.FieldFilter("state", "==", "PARKED"))
        )
        records = [from_document(doc.id, doc.to_dict()) async for doc in query.stream()]
    except GoogleAPIError as exc:
        raise ApprovalUnavailable(f"{COLLECTION}: {exc}") from exc
    return sorted(records, key=lambda record: record.parked_at)


async def resolve(
    approval_id_: str,
    *,
    state: ApprovalState,
    approver: str,
    now: datetime,
    client: Any | None = None,
) -> Approval:
    """Mark a parked approval answered. `PARKED -> APPROVED | DENIED`, once and only once.

    The refusal is the load-bearing part: without it a replayed `POST /approvals/{id}` would
    run `incident.resume()` a second time and execute the action twice. It re-reads the
    record itself rather than trusting one the caller found, because the read and the write
    are two moments — the same reason `policy.expire()` re-reads the version in force.
    """
    if state not in _RESOLVED_STATES:
        raise ApprovalError(f"state: expected one of {_RESOLVED_STATES}, got {state!r}")
    check_approver(approver)
    record = await get(approval_id_, client=client)
    if record.state != "PARKED":
        raise ApprovalNotPending(
            f"{COLLECTION}/{approval_id_}: already {record.state} by {record.approver!r}"
        )
    resolved_at = now.astimezone(UTC).strftime(TIMESTAMP)
    try:
        await (
            _db(client)
            .collection(COLLECTION)
            .document(approval_id_)
            .update({"state": state, "approver": approver, "resolved_at": resolved_at})
        )
    except GoogleAPIError as exc:
        raise ApprovalUnavailable(f"{COLLECTION}/{approval_id_}: {exc}") from exc
    return Approval(
        id=record.id,
        incident_id=record.incident_id,
        state=state,
        proposal=record.proposal,
        subject=record.subject,
        held_signature=record.held_signature,
        entity_ids=record.entity_ids,
        domain=record.domain,
        routed_to=record.routed_to,
        trigger_target=record.trigger_target,
        trigger_signal=record.trigger_signal,
        trigger_observed_value=record.trigger_observed_value,
        trace_id=record.trace_id,
        parked_at=record.parked_at,
        resolved_at=resolved_at,
        approver=approver,
    )
