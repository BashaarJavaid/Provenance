"""The approval queue: what a park guarantees, and what it must never do (item 30).

The item's line is "nothing auto-approves on timeout", and §7.3's row is "held actions stay
parked". Both are claims about an *absence*, which is the hardest kind to keep: nothing here
expires, so nothing here fails when expiry breaks. So the load-bearing tests in this file are
the two that assert the absences directly — a park that no elapsed time resolves, and a
resolution that happens exactly once. Without them, "nothing auto-approves" and "we have not
written that yet" pass the same suite.
"""

from __future__ import annotations

import asyncio
import inspect
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from google.api_core.exceptions import ServiceUnavailable
from test_registry import FakeFirestore

from provenance import approvals

NOW = datetime(2026, 8, 26, 12, 0, 0, tzinfo=UTC)
HELD_SIGNATURE = "ecdsa:deadbeef"
A_PROPOSAL: dict[str, Any] = {
    "action_class": "ROLLBACK_CONFIG",
    "target": "inventory-api",
    "target_tier": "tier2",
    "blast_radius": "single-service",
    "reversible": True,
    "evidence_refs": ["ev-118"],
    "success_predicate": "error_rate < 0.05 within 10m",
    "proposed_by": "remediation-planner@v3",
}


def a_store() -> FakeFirestore:
    return FakeFirestore({}, approvals={})


def park(
    store: FakeFirestore,
    *,
    signature: str = HELD_SIGNATURE,
    incident_id: str = "inc-abc123",
    proposal: dict[str, Any] | None = None,
    now: datetime = NOW,
) -> approvals.Approval:
    return asyncio.run(
        approvals.park(
            incident_id=incident_id,
            proposal=A_PROPOSAL if proposal is None else proposal,
            subject="remediation-planner@v3|ROLLBACK_CONFIG|inventory-api",
            held_signature=signature,
            entity_ids=("belief-inventory-api",),
            domain="infrastructure",
            routed_to="sre-infra-agent",
            trigger_target="inventory-api",
            trigger_signal="error_rate",
            trigger_observed_value=0.38,
            trace_id="9a0b237f4f576fc4da35e4e76bd0ee03",
            now=now,
            client=store,
        )
    )


def resolve(
    store: FakeFirestore,
    record_id: str,
    *,
    state: approvals.ApprovalState = "APPROVED",
    approver: str = "dana.ruiz",
    now: datetime = NOW,
) -> approvals.Approval:
    return asyncio.run(
        approvals.resolve(record_id, state=state, approver=approver, now=now, client=store)
    )


def pending(store: FakeFirestore) -> list[approvals.Approval]:
    return asyncio.run(approvals.pending(client=store))


def stored(store: FakeFirestore) -> dict[str, dict[str, Any]]:
    return store.collections[approvals.COLLECTION]


# --- the load-bearing properties ---------------------------------------------------------------


def test_nothing_in_this_module_consults_a_clock() -> None:
    # §7.3: "held actions stay parked; nothing auto-approves on timeout." That is a claim about
    # an absence, so it is checked as one. Every timestamp here arrives as a caller's `now` and
    # is *written*, never compared: there is no wall-clock read and no comparison between two
    # times anywhere in the module, which is what makes an expiry impossible rather than merely
    # unwritten. Adding `if now > record.parked_at + TTL:` fails this line before it can run.
    source = inspect.getsource(approvals)
    assert "datetime.now" not in source
    assert "timedelta" not in source
    assert "parked_at <" not in source and "parked_at >" not in source


def test_a_park_stays_parked_however_long_it_waits() -> None:
    # The behavioural half of the test above: the queue is read the way `GET /approvals` reads
    # it, twice, and the record is what it was. Nothing but a verdict moves it.
    store = a_store()
    record = park(store)
    for _ in range(2):
        assert asyncio.run(approvals.get(record.id, client=store)).state == "PARKED"
        assert [r.id for r in pending(store)] == [record.id]
    assert stored(store)[record.id]["resolved_at"] == ""
    assert stored(store)[record.id]["approver"] == ""


def test_a_verdict_is_given_exactly_once() -> None:
    # Without this a replayed `POST /approvals/{id}` runs `incident.resume()` twice, and the
    # second run executes an action a human authorized once.
    store = a_store()
    record = park(store)
    assert resolve(store, record.id).state == "APPROVED"
    with pytest.raises(approvals.ApprovalNotPending):
        resolve(store, record.id, state="DENIED", approver="someone.else")
    assert stored(store)[record.id]["state"] == "APPROVED"
    assert stored(store)[record.id]["approver"] == "dana.ruiz"


# --- parking -----------------------------------------------------------------------------------


def test_a_park_is_content_addressed_from_the_held_signature() -> None:
    store = a_store()
    record = park(store)
    assert record.id == approvals.approval_id(HELD_SIGNATURE)
    assert record.state == "PARKED"
    assert record.parked_at == "2026-08-26T12:00:00Z"


def test_re_parking_the_same_decision_is_the_same_document() -> None:
    # `create`-if-absent, `audit.record()`'s posture: a record somebody has since answered must
    # not be returned to PARKED by a replay.
    store = a_store()
    first = park(store)
    resolve(store, first.id, state="DENIED")
    again = park(store)
    assert again.id == first.id
    assert again.state == "DENIED"
    assert len(stored(store)) == 1


def test_two_different_holds_are_two_queue_entries() -> None:
    store = a_store()
    park(store, signature="ecdsa:aaaa")
    park(store, signature="ecdsa:bbbb")
    assert len(pending(store)) == 2


def test_the_park_carries_what_a_resume_needs_and_nothing_it_can_recompute() -> None:
    store = a_store()
    record = park(store)
    # What the fleet actually did, which a resume must not re-derive: the beliefs it reasoned
    # from, the domain it routed to, and the trigger that woke it.
    assert record.entity_ids == ("belief-inventory-api",)
    assert (record.domain, record.routed_to) == ("infrastructure", "sre-infra-agent")
    assert (record.trigger_target, record.trigger_signal) == ("inventory-api", "error_rate")
    # And the proposal as emitted — an input to `gateway.resolve()`, not a conclusion.
    assert record.proposal == A_PROPOSAL


def test_a_park_survives_a_round_trip_through_the_document() -> None:
    # The whole point of the collection: the record outlives the process that wrote it, so the
    # parse has to be exact rather than approximately right.
    store = a_store()
    record = park(store)
    assert approvals.from_document(record.id, stored(store)[record.id]) == record


def test_an_unwritable_queue_raises_rather_than_returning_none() -> None:
    # §7.3, and `audit.py`'s posture: a held action nobody can find is a silent drop.
    store = FakeFirestore({}, error=ServiceUnavailable("down"), approvals={})
    with pytest.raises(approvals.ApprovalUnavailable):
        park(store)


# --- reading -----------------------------------------------------------------------------------


def test_an_absent_approval_is_not_found_rather_than_unavailable() -> None:
    # Two different facts: one is "you asked for something that is not there", the other is
    # "the store is down". `/approvals/{id}` renders them as 404 and 503.
    with pytest.raises(approvals.ApprovalNotFound):
        asyncio.run(approvals.get("appr-nothing", client=a_store()))


def test_pending_returns_only_parked_records_oldest_first() -> None:
    store = a_store()
    later = park(store, signature="ecdsa:bbbb", now=NOW + timedelta(minutes=5))
    earlier = park(store, signature="ecdsa:aaaa", now=NOW)
    answered = park(store, signature="ecdsa:cccc", now=NOW + timedelta(minutes=1))
    resolve(store, answered.id)
    assert [r.id for r in pending(store)] == [earlier.id, later.id]


def test_an_unreadable_queue_is_not_an_empty_one() -> None:
    # The one wrong answer this surface can give: telling a human nothing needs them.
    store = FakeFirestore({}, error=ServiceUnavailable("down"), approvals={})
    with pytest.raises(approvals.ApprovalUnavailable):
        pending(store)


def test_a_malformed_record_raises_rather_than_defaulting() -> None:
    store = a_store()
    record = park(store)
    del stored(store)[record.id]["domain"]
    with pytest.raises(approvals.ApprovalError):
        asyncio.run(approvals.get(record.id, client=store))


# --- resolving ---------------------------------------------------------------------------------


def test_a_resolution_records_who_answered_and_when() -> None:
    store = a_store()
    record = park(store)
    answered = resolve(store, record.id, state="DENIED", now=NOW + timedelta(minutes=6))
    assert (answered.state, answered.approver) == ("DENIED", "dana.ruiz")
    assert answered.resolved_at == "2026-08-26T12:06:00Z"
    # Everything the park established is carried forward untouched.
    assert (answered.proposal, answered.entity_ids, answered.trace_id) == (
        record.proposal,
        record.entity_ids,
        record.trace_id,
    )


def test_a_resolution_never_returns_a_record_to_the_queue() -> None:
    store = a_store()
    record = park(store)
    with pytest.raises(approvals.ApprovalError):
        resolve(store, record.id, state="PARKED")
    assert stored(store)[record.id]["state"] == "PARKED"


def test_resolving_something_absent_is_not_found() -> None:
    with pytest.raises(approvals.ApprovalNotFound):
        resolve(a_store(), "appr-nothing")


@pytest.mark.parametrize(
    "approver",
    ["", " ", "-leading", "a" * 65, "dana ruiz", "dana\nruiz", "<script>", "dana\x00ruiz"],
)
def test_an_approver_that_is_not_an_identifier_is_refused(approver: str) -> None:
    # §8.1 admits identifiers, and this is the boundary between an HTTP body and the trace.
    # The check is here rather than at the exporter so a bad value never reaches a write.
    with pytest.raises(approvals.ApprovalError):
        approvals.check_approver(approver)


@pytest.mark.parametrize("approver", ["dana.ruiz", "dana", "d.ruiz@cymbal.example", "ops-1"])
def test_an_ordinary_identifier_is_accepted(approver: str) -> None:
    assert approvals.check_approver(approver) == approver


def test_an_unresolvable_write_raises_and_leaves_the_park_answerable() -> None:
    store = a_store()
    record = park(store)
    store.error = ServiceUnavailable("down")
    with pytest.raises(approvals.ApprovalUnavailable):
        resolve(store, record.id)
    store.error = None
    assert asyncio.run(approvals.get(record.id, client=store)).state == "PARKED"
