"""The authorization ledger: what a retraction flags, and what it must leave alone (item 15).

`ARCHITECTURE.md` §10's retraction row is "retract a belief and assert every action authorized
on it is flagged in the audit log". Half of that lives in `test_policy.py`, where the
retraction happens; this file guards the ledger itself, and the load-bearing test is the one
that asserts a record citing a *different* belief is untouched. Without it, "flag every action
authorized on this belief" and "flag everything" pass the same suite, and the §6.4 claim —
knowing which past decisions rested on the wrong thing — would be a claim about nothing.
"""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from google.api_core.exceptions import ServiceUnavailable
from test_registry import FakeFirestore

from provenance import audit

NOW = datetime(2026, 8, 22, 12, 0, 0, tzinfo=UTC)
LATER = NOW + timedelta(hours=1)
BELIEF_ID = "belief-inventory-api"
OTHER_BELIEF = "belief-pricing-api"


def a_store() -> FakeFirestore:
    return FakeFirestore({}, authorizations={})


def record(
    store: FakeFirestore,
    *,
    signature: str = "ecdsa:aaaa",
    belief_ids: tuple[str, ...] = (BELIEF_ID,),
    target: str = "inventory-api",
    now: datetime = NOW,
) -> audit.Authorization:
    return asyncio.run(
        audit.record(
            agent_id="remediation-planner",
            action_class="ROLLBACK_CONFIG",
            target=target,
            outcome="APPROVE",
            subject=f"remediation-planner@v3|ROLLBACK_CONFIG|{target}",
            signature=signature,
            belief_ids=belief_ids,
            now=now,
            client=store,
        )
    )


def flag(store: FakeFirestore, *, belief_id: str = BELIEF_ID, version: int = 1) -> int:
    return asyncio.run(audit.flag(belief_id, version=version, now=LATER, client=store))


def stored(store: FakeFirestore) -> dict[str, dict[str, Any]]:
    return store.collections["authorizations"]


# --- recording --------------------------------------------------------------------------------


def test_an_authorized_action_is_recorded_with_the_beliefs_it_rested_on() -> None:
    store = a_store()
    entry = record(store)

    assert stored(store)[entry.id]["belief_ids"] == [BELIEF_ID]
    assert stored(store)[entry.id]["signature"] == "ecdsa:aaaa"
    assert stored(store)[entry.id]["flagged_by"] == []


def test_the_record_id_is_derived_from_the_decision_signature() -> None:
    """Content-addressed, as `beliefs.evidence_id()` is, so a replay is the same document."""
    assert audit.authorization_id("ecdsa:aaaa") == audit.authorization_id("ecdsa:aaaa")
    assert audit.authorization_id("ecdsa:aaaa") != audit.authorization_id("ecdsa:bbbb")


def test_re_recording_the_same_decision_does_not_overwrite_its_flags() -> None:
    """Create-if-absent. A replay must not be able to erase a review mark (§6.4)."""
    store = a_store()
    entry = record(store)
    assert flag(store) == 1

    record(store)  # the same decision, arriving twice

    assert len(stored(store)) == 1
    assert stored(store)[entry.id]["flagged_by"] == [
        {"belief_id": BELIEF_ID, "version": 1, "flagged_at": LATER.strftime(audit.TIMESTAMP)}
    ]


# --- flagging ---------------------------------------------------------------------------------


def test_flagging_marks_every_action_that_rested_on_the_belief() -> None:
    store = a_store()
    first = record(store, signature="ecdsa:aaaa")
    second = record(store, signature="ecdsa:bbbb")

    assert flag(store) == 2

    for entry in (first, second):
        marks = stored(store)[entry.id]["flagged_by"]
        assert marks == [
            {"belief_id": BELIEF_ID, "version": 1, "flagged_at": LATER.strftime(audit.TIMESTAMP)}
        ]


def test_an_action_that_rested_on_a_different_belief_is_never_flagged() -> None:
    """The whole claim. "Every action authorized on it" is not "every action"."""
    store = a_store()
    ours = record(store, signature="ecdsa:aaaa", belief_ids=(BELIEF_ID,))
    theirs = record(store, signature="ecdsa:bbbb", belief_ids=(OTHER_BELIEF,), target="pricing-api")

    assert flag(store) == 1

    assert stored(store)[ours.id]["flagged_by"] != []
    assert stored(store)[theirs.id]["flagged_by"] == []


def test_an_action_resting_on_several_beliefs_is_flagged_by_each_of_them() -> None:
    store = a_store()
    entry = record(store, belief_ids=(BELIEF_ID, OTHER_BELIEF))

    assert flag(store, belief_id=BELIEF_ID) == 1
    assert flag(store, belief_id=OTHER_BELIEF) == 1

    marks = stored(store)[entry.id]["flagged_by"]
    assert [mark["belief_id"] for mark in marks] == [BELIEF_ID, OTHER_BELIEF]


def test_flagging_the_same_version_twice_adds_no_second_mark() -> None:
    """Idempotent: re-running a retraction cannot inflate the count or the list."""
    store = a_store()
    entry = record(store)

    assert flag(store, version=1) == 1
    assert flag(store, version=1) == 0

    assert len(stored(store)[entry.id]["flagged_by"]) == 1


def test_retracting_a_later_version_of_the_same_belief_marks_it_again() -> None:
    """Two retractions of one belief are two different reviews, not a duplicate."""
    store = a_store()
    entry = record(store)

    assert flag(store, version=1) == 1
    assert flag(store, version=4) == 1

    assert [mark["version"] for mark in stored(store)[entry.id]["flagged_by"]] == [1, 4]


def test_flagging_a_belief_nothing_rested_on_flags_nothing() -> None:
    store = a_store()
    record(store, belief_ids=(OTHER_BELIEF,))

    assert flag(store, belief_id=BELIEF_ID) == 0


# --- fail-closed (§7.3) -------------------------------------------------------------------------


def test_an_unreachable_ledger_raises_rather_than_flagging_nothing() -> None:
    """ "Nothing rested on this belief" and "we could not look" must not both return 0."""
    store = FakeFirestore({}, authorizations={})
    record(store)
    store.error = ServiceUnavailable("firestore is down")

    with pytest.raises(audit.AuditUnavailable):
        flag(store)


def test_an_unreachable_ledger_raises_rather_than_dropping_the_record() -> None:
    store = FakeFirestore({}, error=ServiceUnavailable("firestore is down"), authorizations={})

    with pytest.raises(audit.AuditUnavailable):
        record(store)


def test_a_missing_record_raises_rather_than_reading_as_empty() -> None:
    with pytest.raises(audit.AuditError):
        asyncio.run(audit.read("auth-nope", client=a_store()))


def test_a_malformed_stored_record_raises() -> None:
    store = a_store()
    entry = record(store)
    del stored(store)[entry.id]["belief_ids"]

    with pytest.raises(audit.AuditError):
        asyncio.run(audit.read(entry.id, client=store))
