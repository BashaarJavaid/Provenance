"""The offline half of ROADMAP item 12: the store is append-only, and the chain is intact.

The live half is `scripts/verify_belief_store.py`, which does the same thing against real
Firestore -- which matters here more than usual, because "the old version survives" rests on
`create()` refusing to overwrite, and a fake asserting that is asserting our belief about
Firestore rather than Firestore itself.

The two load-bearing tests are `test_the_superseded_version_is_untouched_by_the_write_that
_supersedes_it` and `test_the_store_only_ever_grows`. Everything else in Phase 4 -- item 13's
novelty check, item 14's flip, item 15's retraction, item 17's inspector -- reads a chain
these two are what keep honest.
"""

from __future__ import annotations

import asyncio
import inspect
import types
from copy import deepcopy
from dataclasses import replace
from typing import Any, Union, get_args, get_origin, get_type_hints

import pytest
from google.api_core.exceptions import ServiceUnavailable
from test_registry import FakeFirestore

from provenance import beliefs

ENTITY = "inventory-api"
BELIEF_ID = f"belief-{ENTITY}"
VERSIONS = f"{beliefs.COLLECTION}/{BELIEF_ID}/versions"
STATUS = "CONFIG_REGRESSION_PRONE"


def an_evidence(item_id: str = "ev-1", **overrides: Any) -> beliefs.Evidence:
    # `replace`, as `test_policy.py`'s twin does: every field is named below, so passing
    # `**overrides` to the constructor collides on any of them rather than overriding it.
    return replace(
        beliefs.Evidence(
            id=item_id,
            source_id=f"firestore:services/{ENTITY}",
            source_class="verified_system_observation",
            observed_at="2026-08-22T12:00:00Z",
            ingested_at="2026-08-22T12:00:00Z",
            payload_hash="a" * 64,
            verifiable_by=f"re-read services/{ENTITY}",
        ),
        **overrides,
    )


def a_version(version: int, **overrides: Any) -> beliefs.BeliefVersion:
    fields: dict[str, Any] = {
        "belief_id": BELIEF_ID,
        "version": version,
        "scope": "ENTITY",
        "domain": "infrastructure",
        "entity": ENTITY,
        "status": STATUS,
        "confidence": 0.60,
        "threshold": 0.50,
        "evidence_ids": (f"ev-{version}",),
        "authority": "sre-infra-agent@v1 (standing: GOOD)",
        "committed_at": "2026-08-22T12:00:00Z",
        "committed_by": "memory-policy-engine",
        "signature": "ecdsa:beef",
        "supersedes": None if version == 1 else version - 1,
        "half_life_days": 30.0,
        "expires_at": "2026-09-21T12:00:00Z",
        "on_expiry": "REVERIFY",
    }
    return beliefs.BeliefVersion(**(fields | overrides))


def append(store: FakeFirestore, version: beliefs.BeliefVersion, *evidence: Any) -> None:
    asyncio.run(beliefs.append(version, evidence or (an_evidence(),), client=store))


# --- the verify line ------------------------------------------------------------------------


def test_the_superseded_version_is_untouched_by_the_write_that_supersedes_it() -> None:
    # ROADMAP item 12's verify line, first half: "committing a superseding belief leaves the
    # old version intact and linked". Intact is asserted as byte-identical, not as "close
    # enough" -- forward-only links exist precisely so a commit never writes to v1 again.
    store = FakeFirestore({})
    append(store, a_version(1), an_evidence("ev-1"))
    before = deepcopy(store.collections[VERSIONS]["1"])

    append(store, a_version(2), an_evidence("ev-2"))

    assert store.collections[VERSIONS]["1"] == before
    assert store.collections[VERSIONS]["2"]["supersedes"] == 1


def test_the_store_only_ever_grows() -> None:
    # The second half: "nothing is ever deleted". No function in this module deletes, and the
    # document set after the second write is a superset of the one after the first.
    store = FakeFirestore({})
    append(store, a_version(1), an_evidence("ev-1"))
    after_first = {(name, doc_id) for name, docs in store.collections.items() for doc_id in docs}

    append(store, a_version(2), an_evidence("ev-2"))

    after_second = {(name, doc_id) for name, docs in store.collections.items() for doc_id in docs}
    assert after_first < after_second
    assert not any("delete" in name for name in vars(beliefs))


def test_history_returns_every_version_with_the_backlink_derived() -> None:
    # `superseded_by` is never stored, so it cannot go stale or disagree with `supersedes`.
    store = FakeFirestore({})
    append(store, a_version(1), an_evidence("ev-1"))
    append(store, a_version(2), an_evidence("ev-2"))
    append(store, a_version(3), an_evidence("ev-3"))

    chain = asyncio.run(beliefs.history(BELIEF_ID, client=store))

    assert [v.version for v in chain] == [1, 2, 3]
    assert [v.superseded_by for v in chain] == [2, 3, None]
    assert [v.supersedes for v in chain] == [None, 1, 2]
    assert "superseded_by" not in store.collections[VERSIONS]["1"]


def test_current_is_the_newest_version_that_exists() -> None:
    # No `current_version` pointer: the walk stops at the first miss, so the newest existing
    # version *is* the current one and there is no second field to fall out of step with it.
    store = FakeFirestore({})
    append(store, a_version(1), an_evidence("ev-1"))
    assert asyncio.run(beliefs.current(BELIEF_ID, client=store)).version == 1

    append(store, a_version(2), an_evidence("ev-2"))
    assert asyncio.run(beliefs.current(BELIEF_ID, client=store)).version == 2


# --- fail-closed ------------------------------------------------------------------------------


def test_rewriting_an_existing_version_is_refused() -> None:
    # `create()`, not `set()`. This is the whole append-only guarantee: overwriting is the
    # store's refusal, not our discipline.
    store = FakeFirestore({})
    append(store, a_version(1))

    with pytest.raises(beliefs.VersionConflict):
        append(store, a_version(1, status="SOMETHING_ELSE"))

    assert store.collections[VERSIONS]["1"]["status"] == STATUS


def test_an_unknown_belief_raises_rather_than_reading_as_empty() -> None:
    store = FakeFirestore({})
    with pytest.raises(beliefs.BeliefNotFound):
        asyncio.run(beliefs.current(BELIEF_ID, client=store))


def test_an_unreachable_store_raises_rather_than_reading_as_absent() -> None:
    # §7.3: "we could not read it" must not be indistinguishable from "there is nothing
    # there" -- the second would let item 14 commit a v1 over a belief that already exists.
    store = FakeFirestore({}, error=ServiceUnavailable("firestore is down"))
    with pytest.raises(beliefs.BeliefStoreUnavailable):
        asyncio.run(beliefs.current(BELIEF_ID, client=store))


def test_no_store_function_returns_an_optional_version_or_evidence() -> None:
    # The same structural rule `registry.py` follows: `BeliefVersion | None` is one forgotten
    # `if belief:` away from a missing belief reading as "no belief was there". `Evidence` is
    # on the list for item 13's sake — an unresolvable citation that reads as absent would
    # make §2.2's novelty check compare against an emptier history than the belief has.
    for name, fn in vars(beliefs).items():
        if not inspect.isfunction(fn) or fn.__module__ != beliefs.__name__:
            continue
        returns = get_type_hints(fn).get("return")
        if get_origin(returns) in (Union, types.UnionType):
            args = get_args(returns)
            assert not (beliefs.BeliefVersion in args and type(None) in args), name
            assert not (beliefs.Evidence in args and type(None) in args), name


# --- evidence (§3.3) ---------------------------------------------------------------------------


def test_evidence_is_written_once_and_cited_by_id() -> None:
    # §3.2 renders a belief's evidence as ids. Normalising it is what lets item 13's novelty
    # check read `(source_id, observed_at)` from one place instead of scanning every version.
    store = FakeFirestore({})
    shared = an_evidence("ev-shared")
    append(store, a_version(1, evidence_ids=("ev-shared",)), shared)
    first = deepcopy(store.collections[beliefs.EVIDENCE_COLLECTION]["ev-shared"])

    append(store, a_version(2, evidence_ids=("ev-shared", "ev-2")), shared, an_evidence("ev-2"))

    assert store.collections[beliefs.EVIDENCE_COLLECTION]["ev-shared"] == first
    assert set(store.collections[beliefs.EVIDENCE_COLLECTION]) == {"ev-shared", "ev-2"}
    assert store.collections[VERSIONS]["2"]["evidence"] == ["ev-shared", "ev-2"]


def test_the_version_document_is_written_after_the_evidence_it_cites() -> None:
    # A crash between the two must never leave a version citing provenance the store cannot
    # produce. Evidence with no version yet is harmless; the reverse is a belief that lies.
    store = FakeFirestore({})
    written: list[str] = []
    original = FakeFirestore.collection

    def record(self: FakeFirestore, name: str) -> Any:
        written.append(name)
        return original(self, name)

    FakeFirestore.collection = record  # type: ignore[method-assign]
    try:
        append(store, a_version(1))
    finally:
        FakeFirestore.collection = original  # type: ignore[method-assign]

    assert written.index(beliefs.EVIDENCE_COLLECTION) < written.index(VERSIONS)


def test_a_malformed_version_document_raises() -> None:
    store = FakeFirestore({})
    store.collections[beliefs.COLLECTION] = {BELIEF_ID: {"belief_id": BELIEF_ID}}
    store.collections[VERSIONS] = {"1": {"belief_id": BELIEF_ID}}

    with pytest.raises(beliefs.BeliefStoreError):
        asyncio.run(beliefs.current(BELIEF_ID, client=store))


# --- §2.2 stage 3, the novelty check (item 13) ---------------------------------------------------


def test_a_duplicate_pair_is_not_new_and_the_same_source_later_is() -> None:
    """`ARCHITECTURE.md` §10's novelty row, both halves, as a pure function.

    §2.2 defines new as `(source_id, observed_at)` not already present — the pair, not the
    id and not the payload. So a second reading of the same service an hour on is evidence
    and a re-send of the same instant under a new id is not, which is what makes repetition
    worthless to an attacker without anything having to judge intent.
    """
    known = [an_evidence("ev-1")]
    renamed = an_evidence("ev-renamed")
    later = an_evidence("ev-2", observed_at="2026-08-22T13:00:00Z")
    elsewhere = an_evidence("ev-3", source_id="firestore:services/pricing-api")

    assert beliefs.novel([renamed], known) == ()
    assert beliefs.novel([later], known) == (later,)
    assert beliefs.novel([elsewhere], known) == (elsewhere,)
    assert beliefs.novel([renamed, later], known) == (later,), "order and filtering together"
    assert beliefs.novel([renamed], []) == (renamed,), "nothing known, everything is new"


def test_an_evidence_id_names_the_pair_it_stores() -> None:
    """Content-addressed, so `append()`'s create-if-absent cannot store a disagreeing pair."""
    first = beliefs.evidence_id("firestore:services/inventory-api", "2026-08-22T12:00:00Z")
    assert first == beliefs.evidence_id("firestore:services/inventory-api", "2026-08-22T12:00:00Z")
    assert first != beliefs.evidence_id("firestore:services/inventory-api", "2026-08-22T13:00:00Z")
    assert first != beliefs.evidence_id("firestore:services/pricing-api", "2026-08-22T12:00:00Z")
    assert first.startswith("ev-")


def test_cited_evidence_reads_back_as_the_object_that_was_written() -> None:
    store = FakeFirestore({})
    written = (an_evidence("ev-1"), an_evidence("ev-2", source_class="third_party_audit"))
    append(store, a_version(1, evidence_ids=("ev-1", "ev-2")), *written)

    assert asyncio.run(beliefs.read_evidence(("ev-1", "ev-2"), client=store)) == written
    assert asyncio.run(beliefs.read_evidence((), client=store)) == ()


def test_a_citation_the_store_cannot_answer_raises_rather_than_being_dropped() -> None:
    # A short tuple would make the missing item look like something nobody ever observed, and
    # the next proposal to carry it would be counted as new (§7.3).
    store = FakeFirestore({})
    append(store, a_version(1, evidence_ids=("ev-1",)), an_evidence("ev-1"))
    store.collections[beliefs.EVIDENCE_COLLECTION].clear()

    with pytest.raises(beliefs.BeliefNotFound):
        asyncio.run(beliefs.read_evidence(("ev-1",), client=store))


def test_malformed_stored_evidence_raises() -> None:
    store = FakeFirestore({})
    append(store, a_version(1, evidence_ids=("ev-1",)), an_evidence("ev-1"))
    store.collections[beliefs.EVIDENCE_COLLECTION]["ev-1"] = {"id": "ev-1"}

    with pytest.raises(beliefs.BeliefStoreError):
        asyncio.run(beliefs.read_evidence(("ev-1",), client=store))
