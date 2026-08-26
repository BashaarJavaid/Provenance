"""The Staleness Sweeper: §6.5's clock, and what it is not allowed to do (item 29).

`ARCHITECTURE.md` §10's Sweeper row is three assertions — "expire a belief with no
re-verification source; assert it is `UNKNOWN(stale)`, excluded from recall, never deleted" —
and the third is the one worth defending hardest. A memory system that can delete has no
provenance, and the whole design rests on beliefs being append-only. So the downgrade is
checked to be a *superseding version* whose predecessor is byte-identical, not an edit.

The other property under test here has no line in §10 and would strand the fleet without it:
a swept belief must not be swept again. `expire()` refuses anything already `UNKNOWN` or
`RETRACTED`, and without that refusal a Cloud Run instance left warm overnight would append a
version every five minutes forever — an append-only store's version of a leak.
"""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from conftest import attach_exporter
from google.api_core.exceptions import ServiceUnavailable
from test_policy import ENTITY, a_store, an_evidence
from test_registry import FakeFirestore

from provenance import beliefs, policy, sweeper, telemetry

_EXPORTER = attach_exporter()

# The belief is committed 40 days back, so with a 30-day half-life its `expires_at` is 10 days
# in the past by the time the sweep runs. Every one of those numbers is produced by the
# pipeline — nothing here hand-writes the field the thing under test reads.
NOW = datetime(2026, 8, 26, 12, 0, 0, tzinfo=UTC)
LONG_AGO = NOW - timedelta(days=40)
BELIEF_ID = f"belief-{ENTITY}"
VERSIONS = f"beliefs/{BELIEF_ID}/versions"
STATUS = "CONFIG_REGRESSION_PRONE"


@pytest.fixture
def spans() -> Any:
    _EXPORTER.clear()
    yield _EXPORTER
    _EXPORTER.clear()


def a_stale_store(**overrides: Any) -> FakeFirestore:
    """One belief, committed 40 days ago, in force and long past its clock."""
    store = a_store(**overrides)
    stamp = LONG_AGO.strftime(policy.TIMESTAMP)
    outcome = asyncio.run(
        policy.commit(
            entity=ENTITY,
            domain="infrastructure",
            status=STATUS,
            evidence=[an_evidence(observed_at=stamp, ingested_at=stamp)],
            agent_id="sre-infra-agent",
            now=LONG_AGO,
            client=store,
        )
    )
    assert outcome.outcome == "COMMIT"
    return store


def expire(store: FakeFirestore, *, now: datetime = NOW, belief_id: str = BELIEF_ID) -> Any:
    return asyncio.run(policy.expire(belief_id=belief_id, now=now, client=store))


def sweep(store: FakeFirestore, *, now: datetime = NOW) -> sweeper.Swept:
    return asyncio.run(sweeper.sweep(now=now, client=store))


def versions(store: FakeFirestore) -> dict[str, dict[str, Any]]:
    return store.collections[VERSIONS]


# --- the door -------------------------------------------------------------------------------


def test_a_belief_past_its_clock_is_downgraded_to_unknown() -> None:
    store = a_stale_store()
    outcome = expire(store)
    assert (outcome.outcome, outcome.reason) == ("EXPIRE", "EXPIRED")
    assert versions(store)["2"]["status"] == policy.UNKNOWN
    assert versions(store)["2"]["supersedes"] == 1


def test_the_predecessor_is_left_byte_identical() -> None:
    """§10's "never deleted", and the stronger form of it: never touched either."""
    store = a_stale_store()
    before = dict(versions(store)["1"])
    expire(store)
    assert versions(store)["1"] == before
    assert set(versions(store)) == {"1", "2"}


def test_the_downgrade_carries_the_clock_that_fired() -> None:
    """`expires_at` is the reason the version exists, so a fresh one would erase the reason."""
    store = a_stale_store()
    expire(store)
    v1, v2 = versions(store)["1"], versions(store)["2"]
    assert v2["expires_at"] == v1["expires_at"]
    assert v2["half_life_days"] == v1["half_life_days"]
    # No gate was applied, so no threshold was faced; and a downgrade subtracts nothing from
    # an append-only evidence set.
    assert v2["threshold"] == v1["threshold"]
    assert v2["evidence"] == v1["evidence"]


def test_the_confidence_is_recomputed_as_of_the_sweep() -> None:
    """§4.3 as of now, never a hardcoded zero — 40 days of decay on a 30-day half-life."""
    store = a_stale_store()
    expire(store)
    v1, v2 = versions(store)["1"], versions(store)["2"]
    evidence = asyncio.run(beliefs.read_evidence(v1["evidence"], client=store))
    expected = policy.confidence(evidence, domain="infrastructure", now=NOW)
    assert v2["confidence"] == pytest.approx(expected)
    assert 0 < v2["confidence"] < v1["confidence"]


def test_the_sweeper_is_named_on_the_version_it_writes() -> None:
    store = a_stale_store()
    expire(store)
    v2 = versions(store)["2"]
    assert v2["authority"] == "staleness-sweeper@v1 (§6.5)"
    # Still true, and the reason it is not the Sweeper: this module is the writer either way.
    assert v2["committed_by"] == "memory-policy-engine"


def test_the_outcome_is_signed_and_verifies() -> None:
    store = a_stale_store()
    outcome = expire(store)
    policy.verify_commit(outcome, policy.public_key_pem())
    assert versions(store)["2"]["signature"].startswith("ecdsa:")


@pytest.mark.parametrize("status", [policy.UNKNOWN, policy.RETRACTED])
def test_a_swept_or_retracted_belief_is_never_swept_again(status: str) -> None:
    """Without this the loop appends a version every tick forever."""
    store = a_stale_store()
    versions(store)["1"]["status"] = status
    outcome = expire(store)
    assert (outcome.outcome, outcome.reason) == ("REJECT", "NOT_DUE")
    assert set(versions(store)) == {"1"}


def test_a_belief_inside_its_clock_is_left_alone() -> None:
    store = a_stale_store()
    outcome = expire(store, now=LONG_AGO + timedelta(days=1))
    assert (outcome.outcome, outcome.reason) == ("REJECT", "NOT_DUE")
    assert set(versions(store)) == {"1"}


def test_a_version_with_no_clock_never_expires() -> None:
    """A belief nothing can decay is a belief nothing can declare stale."""
    store = a_stale_store()
    versions(store)["1"]["expires_at"] = ""
    assert expire(store).reason == "NOT_DUE"
    assert set(versions(store)) == {"1"}


def test_expiry_at_exactly_the_stored_instant_is_due() -> None:
    store = a_stale_store()
    at = datetime.strptime(versions(store)["1"]["expires_at"], policy.TIMESTAMP).replace(tzinfo=UTC)
    assert expire(store, now=at).outcome == "EXPIRE"


def test_a_class_belief_expires_by_the_same_path() -> None:
    """§6.5 carves out no scope, and a stale generalization reorders hypotheses just as wrongly."""
    store = a_stale_store()
    versions(store)["1"]["scope"] = "CLASS"
    versions(store)["1"]["statement"] = "services rolled back without a config diff regress"
    expire(store)
    v2 = versions(store)["2"]
    assert (v2["scope"], v2["status"]) == ("CLASS", policy.UNKNOWN)
    assert v2["statement"] == versions(store)["1"]["statement"]


def test_a_lost_race_loses_rather_than_clobbers() -> None:
    """A commit landing between the read and the write wins; the sweep reports it and moves on.

    `expire()` re-reads the version in force precisely to narrow this window to `append()`'s
    own `create()`, which is where Firestore decides it — so the raise is where the race is.
    """
    store = a_stale_store()

    async def lost(*_: Any, **__: Any) -> None:
        raise beliefs.VersionConflict("another writer got version 2")

    with pytest.MonkeyPatch.context() as patch:
        patch.setattr(beliefs, "append", lost)
        outcome = expire(store)
    assert (outcome.outcome, outcome.reason) == ("REJECT", "VERSION_CONFLICT")
    assert set(versions(store)) == {"1"}


def test_an_unwritable_store_refuses_rather_than_raising() -> None:
    """A decision was made and could not be carried out. Refusals do not raise (§7.3)."""
    store = a_stale_store()

    async def down(*_: Any, **__: Any) -> None:
        raise beliefs.BeliefStoreUnavailable("firestore is down")

    with pytest.MonkeyPatch.context() as patch:
        patch.setattr(beliefs, "append", down)
        outcome = expire(store)
    assert (outcome.outcome, outcome.reason) == ("REJECT", "STORE_UNAVAILABLE")
    assert set(versions(store)) == {"1"}


def test_an_unreadable_belief_raises_rather_than_reporting_a_decision() -> None:
    """There is no entity, domain or status to report a decision about, so there is no decision.

    The Sweeper catches it and comes back next tick. A refusal here would put a span on the
    wire claiming something about a belief nothing could read.
    """
    store = a_stale_store()
    store.error = ServiceUnavailable("firestore is down")
    with pytest.raises(beliefs.BeliefStoreUnavailable):
        expire(store)


def test_an_expiry_costs_no_agent_its_standing() -> None:
    """There is no proposing agent, so there is nobody a refusal could be counted against."""
    assert "EXPIRED" not in policy.COUNTED_REJECTIONS
    assert "NOT_DUE" not in policy.COUNTED_REJECTIONS
    store = a_stale_store()
    before = dict(store.docs["sre-infra-agent"])
    expire(store)
    expire(store)  # the second is a NOT_DUE, which is the refusal a counter would notice
    assert store.docs["sre-infra-agent"] == before


# --- the span -------------------------------------------------------------------------------


def test_the_expiry_lands_on_the_one_belief_span(spans: Any) -> None:
    store = a_stale_store()
    spans.clear()
    expire(store)
    (span,) = [s for s in spans.get_finished_spans() if s.name == telemetry.SPAN_BELIEF_COMMIT]
    attrs = dict(span.attributes)
    assert attrs["provenance.decision.outcome"] == "EXPIRE"
    assert attrs["provenance.decision.reason"] == "EXPIRED"
    assert attrs["provenance.belief.status"] == policy.UNKNOWN
    # "a clock fired" and "an agent asserted this" must not look alike to anyone reading it.
    assert attrs["provenance.agent.id"] == "staleness-sweeper"
    assert attrs["provenance.agent.version"] == "v1"
    assert attrs["provenance.agent.standing"] == "GOOD"


def test_the_other_two_doors_still_report_the_agent_that_proposed(spans: Any) -> None:
    """Item 29's overrides are defaulted, so `commit()` is unchanged where it was already right."""
    store = a_store()
    spans.clear()
    asyncio.run(
        policy.commit(
            entity=ENTITY,
            domain="infrastructure",
            status=STATUS,
            evidence=[an_evidence()],
            agent_id="sre-infra-agent",
            now=NOW,
            client=store,
        )
    )
    (span,) = [s for s in spans.get_finished_spans() if s.name == telemetry.SPAN_BELIEF_COMMIT]
    attrs = dict(span.attributes)
    assert attrs["provenance.agent.id"] == "sre-infra-agent"
    assert attrs["provenance.agent.version"] == "v1"


# --- the walk -------------------------------------------------------------------------------


def _second_belief(store: FakeFirestore, entity: str, *, at: datetime) -> None:
    stamp = at.strftime(policy.TIMESTAMP)
    outcome = asyncio.run(
        policy.commit(
            entity=entity,
            domain="infrastructure",
            status=STATUS,
            evidence=[
                an_evidence(
                    id=beliefs.evidence_id(f"firestore:services/{entity}", stamp),
                    source_id=f"firestore:services/{entity}",
                    observed_at=stamp,
                    ingested_at=stamp,
                )
            ],
            agent_id="sre-infra-agent",
            now=at,
            client=store,
        )
    )
    assert outcome.outcome == "COMMIT"


def test_a_tick_expires_only_what_is_due() -> None:
    store = a_stale_store()
    _second_belief(store, "pricing-api", at=NOW)  # committed today, nowhere near its clock
    swept = sweep(store)
    assert swept.examined == 2
    assert swept.expired == (BELIEF_ID,)
    assert swept.skipped == ()
    assert set(store.collections["beliefs/belief-pricing-api/versions"]) == {"1"}


def test_a_second_tick_changes_nothing() -> None:
    """Idempotence is what makes 'skip and retry next tick' a safe error posture."""
    store = a_stale_store()
    sweep(store)
    after = {k: dict(v) for k, v in versions(store).items()}
    assert sweep(store).expired == ()
    assert versions(store) == after


def test_one_unreadable_belief_does_not_stop_the_others() -> None:
    store = a_stale_store()
    _second_belief(store, "pricing-api", at=LONG_AGO)
    del store.collections["beliefs/belief-pricing-api/versions"]["1"]  # a root with no versions
    swept = sweep(store)
    assert swept.expired == (BELIEF_ID,)
    assert swept.skipped == ("belief-pricing-api",)


def test_an_unreadable_collection_is_a_tick_that_did_not_happen() -> None:
    """No belief is touched on the strength of a partial read (§7.3)."""
    store = a_stale_store()
    store.error = ServiceUnavailable("firestore is down")
    with pytest.raises(beliefs.BeliefStoreUnavailable):
        sweep(store)
    assert set(versions(store)) == {"1"}


# --- the loop -------------------------------------------------------------------------------


def test_the_loop_outlives_a_failing_tick() -> None:
    """An exception killing the task is a service that silently stops consuming expiry."""
    calls: list[int] = []

    async def boom(**_: Any) -> sweeper.Swept:
        calls.append(1)
        if len(calls) == 1:
            raise RuntimeError("firestore had a moment")
        return sweeper.Swept(examined=0, expired=(), skipped=())

    async def drive() -> None:
        task = asyncio.create_task(sweeper.run_forever(interval=0))
        while len(calls) < 3:
            await asyncio.sleep(0)
        await sweeper.cancel(task)
        assert task.cancelled() or task.done()

    with pytest.MonkeyPatch.context() as patch:
        patch.setattr(sweeper, "sweep", boom)
        asyncio.run(drive())
    assert len(calls) >= 3


def test_the_interval_is_the_published_one() -> None:
    """A number nothing else carries: ~3k Firestore reads/day with a demo tab left open."""
    assert sweeper.SWEEP_INTERVAL_SECONDS == 300
