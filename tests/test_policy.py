"""The Memory Policy Engine: the computed number, the refusals, and the superseding write.

`ARCHITECTURE.md` §10's confidence and novelty rows are item 13's; its Conflict-rule and
Standing rows are item 14's and live here too. What is checked is what the engine claims:
§4.3's arithmetic over the accumulated evidence, the §2.2 stage-2 standing and domain checks,
stage 3's mechanical novelty check, both thresholds, the re-affirmation that supersedes v1
(item 12), §6.3's different-source-class rule, and the standing counter stage 6 increments.

The confidence and novelty tests are the ones that would matter if every other guarantee
held, and they defend the same property from two sides. If restating one observation twice
moved the number, an agent could talk any belief over the threshold by repeating itself —
which is the poisoning attack §6.3 exists to stop. §4.3 stops the *arithmetic* half with a
`max` over distinct source classes; §2.2 stage 3 stops the *bookkeeping* half by refusing the
repetition outright. Neither consults a model.
"""

from __future__ import annotations

import asyncio
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from itertools import pairwise
from typing import Any

import pytest
from conftest import attach_exporter
from google.api_core.exceptions import ServiceUnavailable
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter
from test_registry import FakeFirestore

from provenance import audit, beliefs, policy, registry, telemetry

_EXPORTER = attach_exporter()

NOW = datetime(2026, 8, 22, 12, 0, 0, tzinfo=UTC)
# A *second* observation of the same thing. §2.2 stage 3 keys novelty on `(source_id,
# observed_at)`, so re-reading the same service an hour later is new evidence and handing the
# same instant a fresh id is not — which is what makes repetition worthless to an attacker.
LATER = NOW + timedelta(hours=1)
ENTITY = "inventory-api"
DOMAIN = "infrastructure"
STATUS = "CONFIG_REGRESSION_PRONE"
BELIEF_ID = f"belief-{ENTITY}"
VERSIONS = f"beliefs/{BELIEF_ID}/versions"


@pytest.fixture
def spans() -> Any:
    _EXPORTER.clear()
    yield _EXPORTER
    _EXPORTER.clear()


def an_evidence(**overrides: Any) -> policy.Evidence:
    return replace(
        policy.Evidence(
            id="ev-1",
            source_id=f"firestore:services/{ENTITY}",
            source_class="verified_system_observation",
            observed_at=NOW.strftime(policy.TIMESTAMP),
            ingested_at=NOW.strftime(policy.TIMESTAMP),
            payload_hash="a" * 64,
            verifiable_by=f"re-read services/{ENTITY}",
        ),
        **overrides,
    )


def a_later_evidence(**overrides: Any) -> policy.Evidence:
    """The same sensor reading the same thing an hour on — novel by §2.2, same source class."""
    stamp = LATER.strftime(policy.TIMESTAMP)
    return an_evidence(
        id=beliefs.evidence_id(f"firestore:services/{ENTITY}", stamp),
        observed_at=stamp,
        ingested_at=stamp,
        **overrides,
    )


def a_store(**overrides: Any) -> FakeFirestore:
    record = registry.Agent(
        id="sre-infra-agent",
        version="v1",
        public_key="",
        tool_scope=(),
        memory_domains=("infrastructure",),
        standing="GOOD",
        rejection_window=(),
    )
    return FakeFirestore(
        {"sre-infra-agent": registry.to_document(replace(record, **overrides))},
        beliefs={},
        authorizations={},
    )


def commit(
    store: FakeFirestore,
    evidence: list[policy.Evidence] | None = None,
    status: str = STATUS,
    now: datetime = NOW,
) -> Any:
    return asyncio.run(
        policy.commit(
            entity=ENTITY,
            domain=DOMAIN,
            status=status,
            evidence=evidence if evidence is not None else [an_evidence()],
            agent_id="sre-infra-agent",
            now=now,
            client=store,
        )
    )


def retract(
    store: FakeFirestore,
    evidence: list[policy.Evidence] | None = None,
    now: datetime = NOW,
) -> Any:
    return asyncio.run(
        policy.retract(
            entity=ENTITY,
            domain=DOMAIN,
            evidence=evidence if evidence is not None else [an_evidence()],
            agent_id="sre-infra-agent",
            now=now,
            client=store,
        )
    )


def an_authorization(store: FakeFirestore, *, signature: str, belief_ids: tuple[str, ...]) -> str:
    """One ledger record, as `incident.py`'s authorize node writes it (item 15)."""
    entry = asyncio.run(
        audit.record(
            agent_id="remediation-planner",
            action_class="ROLLBACK_CONFIG",
            target=ENTITY,
            outcome="APPROVE",
            subject=f"remediation-planner@v3|ROLLBACK_CONFIG|{ENTITY}",
            signature=signature,
            belief_ids=belief_ids,
            now=NOW,
            client=store,
        )
    )
    return entry.id


def window(store: FakeFirestore) -> list[dict[str, Any]]:
    """§3.4's `rejection_window` as it is actually stored — the standing counter (§2.2 #6)."""
    stored = store.docs["sre-infra-agent"]["rejection_window"]
    assert isinstance(stored, list)
    return stored


# --- §4.3, the computed number --------------------------------------------------------------


def test_one_fresh_verified_observation_gives_exactly_the_published_weight() -> None:
    """`1 - (1 - 0.60) = 0.60`. The number in §4.3's table, with no decay applied yet."""
    assert policy.confidence([an_evidence()], now=NOW) == pytest.approx(0.60)


def test_restating_one_observation_twice_is_worth_exactly_stating_it_once() -> None:
    """§4.3: "only distinct source classes combine". This is the poisoning defense as arithmetic.

    Two items, same class, same everything but the id — a restatement. If the noisy-OR ran
    over items rather than classes this would be 0.84 and the belief would look corroborated
    by a single reading of a single dial.
    """
    restated = [an_evidence(), an_evidence(id="ev-2")]
    assert policy.confidence(restated, now=NOW) == pytest.approx(0.60)


def test_a_bare_assertion_cannot_move_confidence_at_all() -> None:
    """`unverified_external_claim` weighs 0.00, so it is not weak evidence — it is none."""
    claim = an_evidence(id="ev-x", source_class="unverified_external_claim")
    assert policy.confidence([claim], now=NOW) == pytest.approx(0.0)
    # And it cannot dilute a real one either.
    assert policy.confidence([an_evidence(), claim], now=NOW) == pytest.approx(0.60)


def test_an_aged_observation_weighs_less_than_a_fresh_one() -> None:
    """§6.5: "beliefs weaken on their own". One half-life halves the weight."""
    old = an_evidence(observed_at=(NOW - timedelta(days=30)).strftime(policy.TIMESTAMP))
    assert policy.confidence([old], now=NOW) == pytest.approx(0.30)


def test_age_decay_is_monotonic() -> None:
    """§10's third confidence property: an older observation is never worth more.

    The point is not the curve's shape but its direction. §6.5 has the Sweeper act on a
    belief that drifts toward the threshold, and "drifts toward" is only true if age can
    never buy confidence back. Checked across a ladder rather than at one point, because a
    sign error inside the exponent passes any single-point test that fits it.
    """
    ages = [0, 1, 7, 30, 31, 90, 365, 3650]
    values = [policy.confidence([an_evidence()], now=NOW + timedelta(days=days)) for days in ages]
    assert all(a >= b for a, b in pairwise(values)), values
    assert values[0] == pytest.approx(0.60)
    assert values[ages.index(30)] == pytest.approx(0.30), "one half-life halves the weight"
    assert values[-1] < 0.001, "a decade on, the observation is worth all but nothing"


# --- §2.2, the pipeline ----------------------------------------------------------------------


def test_a_confirmed_observation_commits_the_first_belief(spans: InMemorySpanExporter) -> None:
    store = a_store()
    result = commit(store)

    assert (result.outcome, result.reason) == ("COMMIT", "ABOVE_THRESHOLD")
    assert result.confidence == pytest.approx(0.60)
    assert result.belief_id == BELIEF_ID and result.version == 1

    stored = store.collections[VERSIONS]["1"]
    assert stored["scope"] == "ENTITY"
    assert stored["status"] == STATUS
    assert stored["authority"] == "sre-infra-agent@v1 (standing: GOOD)"
    assert stored["confidence"] == pytest.approx(0.60)
    assert len(stored["evidence"]) == 1
    assert stored["supersedes"] is None
    # §6.5's decay clock, written at commit time so the Sweeper has something to consume.
    assert (stored["half_life_days"], stored["on_expiry"]) == (30.0, "REVERIFY")
    assert stored["expires_at"] == "2026-09-21T12:00:00Z"
    policy.verify_commit(result, policy.public_key_pem())


def test_a_degraded_agents_memory_write_is_rejected_outright(
    spans: InMemorySpanExporter,
) -> None:
    """§3.4, verbatim. The gateway *holds* a DEGRADED agent's action; memory rejects it."""
    store = a_store(standing="DEGRADED")
    result = commit(store)

    assert (result.outcome, result.reason) == ("REJECT", "STANDING_NOT_GOOD")
    assert store.collections["beliefs"] == {}


def test_an_agent_writing_outside_its_domains_is_rejected(spans: InMemorySpanExporter) -> None:
    """Memory-domain authority is per agent (§3.4). The supply-chain agent holds no `sre`."""
    store = a_store(memory_domains=("supply-chain",))
    result = commit(store)

    assert (result.outcome, result.reason) == ("REJECT", "DOMAIN_NOT_HELD")
    assert store.collections["beliefs"] == {}


def test_an_unreadable_registry_rejects_rather_than_committing(
    spans: InMemorySpanExporter,
) -> None:
    """§7.3 fail-closed. An authority check that did not happen is not one that passed."""
    store = a_store()
    store.error = ServiceUnavailable("firestore is down")
    result = commit(store)

    assert (result.outcome, result.reason) == ("REJECT", "REGISTRY_UNAVAILABLE")


def test_evidence_below_the_threshold_does_not_write(spans: InMemorySpanExporter) -> None:
    """0.15 from a single `agent_inference` is under §4.3's 0.50 for a new belief.

    An agent's own reasoning about a system is worth something, and it is worth less than
    half a commit. Nothing about that number is negotiable by the agent that produced it.
    """
    store = a_store()
    result = commit(store, [an_evidence(source_class="agent_inference")])

    assert (result.outcome, result.reason) == ("REJECT", "BELOW_THRESHOLD")
    assert result.confidence == pytest.approx(0.15)
    assert store.collections["beliefs"] == {}


def test_a_re_affirmation_commits_a_superseding_version(spans: InMemorySpanExporter) -> None:
    """ROADMAP item 12's verify line, through the pipeline that owns the write.

    The same status observed again is a re-affirmation, not a flip: v2 supersedes v1, v1 is
    left exactly as it was committed, and the link points backwards only.
    """
    store = a_store()
    first = commit(store)
    stored_v1 = dict(store.collections[VERSIONS]["1"])

    second = commit(store, [a_later_evidence()])

    assert first.outcome == "COMMIT" and first.version == 1
    assert (second.outcome, second.reason) == ("COMMIT", "ABOVE_THRESHOLD")
    assert second.version == 2
    assert store.collections[VERSIONS]["1"] == stored_v1, "v1 was modified"
    assert store.collections[VERSIONS]["2"]["supersedes"] == 1
    span = [s for s in spans.get_finished_spans() if s.name == telemetry.SPAN_BELIEF_COMMIT][-1]
    assert span.attributes is not None
    assert span.attributes["provenance.belief.supersedes"] == 1


# --- §6.3's conflict rule (item 14) ----------------------------------------------------------

FORTNIGHT = NOW + timedelta(days=15)
CLEARED = "CLEARED"


def a_flagging_evidence(**overrides: Any) -> policy.Evidence:
    """§6.3's Aug-1 `contractual_record` — the class that establishes the status in force."""
    return an_evidence(id="ev-118", source_class="contractual_record", **overrides)


def a_fortnight_later(source_class: str, item_id: str, at: datetime = FORTNIGHT) -> policy.Evidence:
    stamp = at.strftime(policy.TIMESTAMP)
    return an_evidence(
        id=item_id,
        source_class=source_class,
        source_id=f"firestore:{source_class}/{ENTITY}",
        observed_at=stamp,
        ingested_at=stamp,
    )


def test_a_flip_below_the_flip_threshold_is_refused_by_the_number(
    spans: InMemorySpanExporter,
) -> None:
    """§4.3's two doors, and the refusal says which one it was.

    A re-affirmation at 0.60 commits; the same evidence claiming the opposite status does not,
    because a flip is judged against 0.70. `BELOW_THRESHOLD` carrying `threshold = 0.70` is the
    honest report — the claim was not refused for lacking corroboration, it was refused for
    not being confident enough to be worth checking corroboration for.
    """
    store = a_store()
    commit(store)

    flip = commit(store, [a_later_evidence()], status="HEALTHY", now=LATER)

    assert (flip.outcome, flip.reason) == ("REJECT", "BELOW_THRESHOLD")
    assert flip.confidence == pytest.approx(0.60)
    assert flip.version == 2
    assert "2" not in store.collections[VERSIONS]
    span = [s for s in spans.get_finished_spans() if s.name == telemetry.SPAN_BELIEF_COMMIT][-1]
    assert span.attributes is not None
    assert span.attributes["provenance.belief.threshold"] == pytest.approx(0.70)
    assert span.attributes["provenance.belief.supersedes"] == 1


def test_a_same_source_class_flip_is_refused_even_above_the_threshold(
    spans: InMemorySpanExporter,
) -> None:
    """ROADMAP item 14's verify line, first half; ARCHITECTURE §10's Conflict-rule row.

    "A single sensor cannot both set and clear an alarm." The belief in force here rests on two
    classes and clears 0.70 comfortably, so the number is not what stops this — the proposal
    adds a *third* reading from a class already in the set, which is corroboration by
    repetition and §6.3 says that is not corroboration at all.

    Note that one class alone can never reach 0.70: the strongest base weight is 0.60 and
    `confidence()` collapses a class to its best item. So this case only exists because a
    version rests on everything it ever rested on (item 13) — which is exactly why the classes
    are read off the accumulated set rather than off the proposal.
    """
    store = a_store()
    commit(store, [a_flagging_evidence()])
    corroborated = commit(
        store,
        [a_fortnight_later("verified_system_observation", "ev-140")],
        now=FORTNIGHT,
    )
    assert corroborated.outcome == "COMMIT"

    flip = commit(
        store,
        [
            a_fortnight_later(
                "verified_system_observation", "ev-141", at=FORTNIGHT + timedelta(hours=1)
            )
        ],
        status=CLEARED,
        now=FORTNIGHT + timedelta(hours=1),
    )

    assert (flip.outcome, flip.reason) == ("REJECT", "FLIP_UNSUPPORTED")
    assert flip.confidence > policy.FLIP_THRESHOLD, "the number was never the obstacle"
    assert "3" not in store.collections[VERSIONS], "a same-class flip wrote a version"
    span = [s for s in spans.get_finished_spans() if s.name == telemetry.SPAN_BELIEF_COMMIT][-1]
    assert span.attributes is not None
    assert span.attributes["provenance.belief.status"] == CLEARED, "what was claimed"
    assert store.collections[VERSIONS]["2"]["status"] == STATUS, "what is still in force"


def test_a_different_source_class_flip_commits(spans: InMemorySpanExporter) -> None:
    """ROADMAP item 14's verify line, second half — §6.3's *legitimate update*, verbatim.

    "Supplier X flagged Aug 1 on late shipments (`contractual_record`). Aug 15 it passes a
    compliance audit (`third_party_audit` — new, verifiable, different class). Confidence
    recomputes, threshold met → commit superseding version." That is 0.71 over the accumulated
    pair and 0.55 over the audit alone, which is the whole reason item 13 accumulates.
    """
    store = a_store()
    commit(store, [a_flagging_evidence()])

    flip = commit(
        store,
        [a_fortnight_later("third_party_audit", "ev-140")],
        status=CLEARED,
        now=FORTNIGHT,
    )

    assert (flip.outcome, flip.reason) == ("COMMIT", "ABOVE_THRESHOLD")
    assert flip.confidence == pytest.approx(0.71, abs=0.005)
    stored = store.collections[VERSIONS]["2"]
    assert stored["status"] == CLEARED
    assert stored["threshold"] == pytest.approx(0.70), "the door it actually passed through"
    assert stored["evidence"] == ["ev-118", "ev-140"], "it rests on what it overturned, too"
    assert stored["supersedes"] == 1
    assert store.collections[VERSIONS]["1"]["status"] == STATUS, "v1 is the reasoning trail"


def test_a_first_belief_is_never_a_flip(spans: InMemorySpanExporter) -> None:
    """There is nothing to contradict, so 0.50 is the door — a status is not a flip by itself.

    Guarding the `previous is not None` half of the rule: without it, the very first belief
    about an entity would be judged against 0.70 and refused for lacking corroboration of a
    status nothing had ever claimed.
    """
    store = a_store()

    first = commit(store, status="ANY_STATUS_AT_ALL")

    assert (first.outcome, first.reason) == ("COMMIT", "ABOVE_THRESHOLD")
    assert store.collections[VERSIONS]["1"]["threshold"] == pytest.approx(0.50)


# --- §2.2 stage 6's standing counter (item 14) -----------------------------------------------


def test_a_refusal_the_agent_caused_increments_its_standing_counter() -> None:
    """§2.2 stage 6: "REJECT (logged, standing counter incremented)".

    §6.3's poisoning case is this line and nothing else: an unverifiable claim weighs 0.00,
    the number does not move, the write is refused — and the attempt is remembered against the
    agent that made it. The reason is stored so item 28's panel can say *why* it degraded.
    """
    store = a_store()

    refused = commit(store, [an_evidence(source_class="unverified_external_claim")])

    assert (refused.outcome, refused.reason) == ("REJECT", "BELOW_THRESHOLD")
    assert refused.confidence == 0.0
    assert [entry["reason"] for entry in window(store)] == ["BELOW_THRESHOLD"]
    assert store.docs["sre-infra-agent"]["standing"] == "GOOD", "one attempt is not three"


def test_an_infrastructure_refusal_does_not_count_against_the_agent() -> None:
    """§3.4 counts "rejected memory writes **lacking verifiable evidence**", not every REJECT.

    An unreadable evidence store is not the proposing agent's doing, and standing has no
    automatic restoration path — so degrading an agent for a Firestore outage would be a
    permanent penalty for someone else's failure.
    """
    store = a_store()
    commit(store)
    store.collections[beliefs.EVIDENCE_COLLECTION].clear()

    unreadable = commit(store, [a_later_evidence()])

    assert (unreadable.outcome, unreadable.reason) == ("REJECT", "STORE_UNAVAILABLE")
    assert window(store) == [], "an outage degraded an agent"


def test_three_refusals_degrade_the_agent_and_its_next_write_is_rejected_outright() -> None:
    """ARCHITECTURE §10's Standing row, and the mechanism item 28's demo beat renders.

    Three rejected writes inside the window → DEGRADED, and §3.4's consequence follows on the
    next proposal: "a DEGRADED agent's memory writes are rejected outright". The fourth claim
    here would otherwise have committed — it is refused for who is asking, not for what it says.
    """
    store = a_store()
    bare = an_evidence(source_class="unverified_external_claim")

    for hour in range(3):
        stamp = (NOW + timedelta(hours=hour)).strftime(policy.TIMESTAMP)
        refused = commit(
            store,
            [an_evidence(id=f"ev-bare-{hour}", observed_at=stamp, source_class=bare.source_class)],
            now=NOW + timedelta(hours=hour),
        )
        assert refused.reason == "BELOW_THRESHOLD"

    assert len(window(store)) == 3
    assert store.docs["sre-infra-agent"]["standing"] == "DEGRADED"

    ordinary = commit(store, [a_later_evidence()], now=LATER)

    assert (ordinary.outcome, ordinary.reason) == ("REJECT", "STANDING_NOT_GOOD")
    assert len(window(store)) == 3, "an already-refused authority is not a fourth rejection"


def test_a_registry_that_cannot_record_the_rejection_does_not_change_the_answer() -> None:
    """The counter write is best-effort; the refusal is not.

    Nothing was committed either way, so a registry that cannot be written costs a missed
    increment. Raising instead would turn a correct refusal into an exception out of the
    incident's resolve node — a fail-closed decision reported as a crash.
    """
    store = a_store()

    class OneShot(FakeFirestore):
        def collection(self, name: str) -> Any:
            if name == registry.COLLECTION and self.docs["sre-infra-agent"].get("_read"):
                self.error = ServiceUnavailable("firestore is down")
            self.docs["sre-infra-agent"]["_read"] = True
            return super().collection(name)

    failing = OneShot(dict(store.docs), beliefs={})

    refused = commit(failing, [an_evidence(source_class="unverified_external_claim")])

    assert (refused.outcome, refused.reason) == ("REJECT", "BELOW_THRESHOLD")
    policy.verify_commit(refused, policy.public_key_pem())


def test_the_span_carries_the_standing_that_governed_the_decision(
    spans: InMemorySpanExporter,
) -> None:
    """§8.1: the span reports what this decision was made under, not what it caused.

    The agent was GOOD when the proposal was evaluated, and the degradation is a consequence
    of the refusal, not an input to it. DEGRADED becoming visible is the registry panel's job.
    """
    store = a_store()
    for hour in range(3):
        stamp = (NOW + timedelta(hours=hour)).strftime(policy.TIMESTAMP)
        commit(
            store,
            [
                an_evidence(
                    id=f"ev-bare-{hour}",
                    observed_at=stamp,
                    source_class="unverified_external_claim",
                )
            ],
            now=NOW + timedelta(hours=hour),
        )

    span = [s for s in spans.get_finished_spans() if s.name == telemetry.SPAN_BELIEF_COMMIT][-1]
    assert span.attributes is not None
    assert span.attributes["provenance.agent.standing"] == "GOOD"
    assert store.docs["sre-infra-agent"]["standing"] == "DEGRADED"


def test_restating_one_source_is_not_a_second_reason_to_believe_it(
    spans: InMemorySpanExporter,
) -> None:
    """ROADMAP item 13's verify line: a duplicate `(source_id, observed_at)` is not new.

    This is the bookkeeping half of the poisoning defense. §4.3's `max` already makes the
    repetition worth nothing arithmetically; stage 3 refuses it before the arithmetic runs,
    so the trace says "you told us nothing new" rather than reporting a number as if a fresh
    judgment had been made. A new id on the same instant does not help — the pair is what is
    compared, so an attacker cannot rename its way past the check.
    """
    store = a_store()
    commit(store)

    repeat = commit(store, [an_evidence(), an_evidence(id="ev-renamed")])

    assert (repeat.outcome, repeat.reason) == ("REJECT", "NO_NEW_EVIDENCE")
    assert "2" not in store.collections[VERSIONS], "a repetition wrote a version"
    span = [s for s in spans.get_finished_spans() if s.name == telemetry.SPAN_BELIEF_COMMIT][-1]
    assert span.attributes is not None
    assert span.attributes["provenance.evidence.novel_count"] == 0
    assert span.attributes["provenance.evidence.ids"] == ("ev-1", "ev-renamed"), "as proposed"


def test_a_first_belief_with_no_evidence_is_refused_by_the_arithmetic(
    spans: InMemorySpanExporter,
) -> None:
    """An evidence-free claim is `BELOW_THRESHOLD`, never `NO_NEW_EVIDENCE`.

    The two refusals mean different things and the distinction is the reason stage 3's gate
    is guarded on there being a predecessor at all. "Nothing new" is a statement about a
    belief that already exists; a first belief supported by nothing has told us nothing at
    all, and what refuses it is ADR-002's arithmetic — confidence 0.00, exactly as a bare
    assertion of `unverified_external_claim` is refused, and by the same door.
    """
    store = a_store()

    empty = commit(store, [])

    assert (empty.outcome, empty.reason) == ("REJECT", "BELOW_THRESHOLD")
    assert empty.confidence == 0.0
    assert store.collections.get(VERSIONS, {}) == {}
    span = [s for s in spans.get_finished_spans() if s.name == telemetry.SPAN_BELIEF_COMMIT][-1]
    assert span.attributes is not None
    assert span.attributes["provenance.evidence.novel_count"] == 0


def test_a_superseding_version_rests_on_everything_it_ever_rested_on(
    spans: InMemorySpanExporter,
) -> None:
    """§3.2's `#17 ev-[118]` → `#42 ev-[118,140,141]`, and §6.3's legitimate-update case.

    The accumulated set is what makes corroboration work across time. A contractual record
    from Aug 1 and an audit from Aug 15 are two distinct source classes even though they
    arrived a fortnight apart, and only the union clears the 0.70 door item 14's flip rule
    needs — 0.71 accumulated against 0.55 for the audit alone. A version that cited only what
    its own proposal carried would make §6.3's worked example unreachable.
    """
    store = a_store()
    flagged = an_evidence(id="ev-118", source_class="contractual_record")
    commit(store, [flagged])

    audited = an_evidence(
        id="ev-140",
        source_class="third_party_audit",
        observed_at=(NOW + timedelta(days=15)).strftime(policy.TIMESTAMP),
    )
    second = asyncio.run(
        policy.commit(
            entity=ENTITY,
            domain=DOMAIN,
            status=STATUS,
            evidence=[audited],
            agent_id="sre-infra-agent",
            now=NOW + timedelta(days=15),
            client=store,
        )
    )

    assert second.outcome == "COMMIT"
    assert store.collections[VERSIONS]["2"]["evidence"] == ["ev-118", "ev-140"]
    # 1 − (1 − 0.50·2^(-15/30))(1 − 0.55); the audit alone would be 0.55 and stop below 0.70.
    assert second.confidence == pytest.approx(0.71, abs=0.005)
    span = [s for s in spans.get_finished_spans() if s.name == telemetry.SPAN_BELIEF_COMMIT][-1]
    assert span.attributes is not None
    assert span.attributes["provenance.evidence.novel_count"] == 1
    assert span.attributes["provenance.evidence.ids"] == ("ev-140",), "what was proposed"


def test_evidence_the_store_cannot_produce_rejects_rather_than_committing(
    spans: InMemorySpanExporter,
) -> None:
    """§7.3 again: a history with holes in it must not read as a history with nothing in it.

    If the cited evidence cannot be resolved, every proposal looks novel and a duplicate
    walks straight through stage 3. Fail closed — the belief in force stands.
    """
    store = a_store()
    commit(store)
    store.collections[beliefs.EVIDENCE_COLLECTION].clear()

    second = commit(store, [a_later_evidence()])

    assert (second.outcome, second.reason) == ("REJECT", "STORE_UNAVAILABLE")
    assert "2" not in store.collections[VERSIONS]


# --- the span --------------------------------------------------------------------------------


def test_the_commit_span_carries_the_arithmetic_and_omits_supersedes(
    spans: InMemorySpanExporter,
) -> None:
    """§8.1: a first belief supersedes nothing, and absent means omitted, never empty."""
    commit(a_store())
    span = next(s for s in spans.get_finished_spans() if s.name == telemetry.SPAN_BELIEF_COMMIT)
    assert span.attributes is not None
    assert span.attributes["provenance.decision.outcome"] == "COMMIT"
    assert span.attributes["provenance.belief.confidence"] == pytest.approx(0.60)
    assert span.attributes["provenance.belief.threshold"] == pytest.approx(0.50)
    assert span.attributes["provenance.evidence.source_classes"] == ("verified_system_observation",)
    assert span.attributes["provenance.decision.signature"].startswith("ecdsa:")
    assert "provenance.belief.supersedes" not in span.attributes


def test_a_rejection_is_on_the_span_too(spans: InMemorySpanExporter) -> None:
    """§2.2 stage 6: "every outcome is signed and audited" — refusals are the ones that matter."""
    commit(a_store(standing="DEGRADED"))
    span = next(s for s in spans.get_finished_spans() if s.name == telemetry.SPAN_BELIEF_COMMIT)
    assert span.attributes is not None
    assert span.attributes["provenance.decision.reason"] == "STANDING_NOT_GOOD"
    assert span.attributes["provenance.agent.standing"] == "DEGRADED"


def test_a_tampered_commit_does_not_verify(spans: InMemorySpanExporter) -> None:
    """The signature covers the outcome, so a REJECT cannot be re-read as a COMMIT."""
    result = commit(a_store())
    forged = replace(result, outcome="RETRACT")
    with pytest.raises(policy.CommitInvalid):
        policy.verify_commit(forged, policy.public_key_pem())


# --- §6.4's retraction (item 15) --------------------------------------------------------------


def test_a_retraction_writes_a_retracted_version_and_leaves_its_predecessor_intact(
    spans: InMemorySpanExporter,
) -> None:
    """§6.4: "produces a `RETRACTED` version with a link to the disproving evidence".

    A retraction is a transition and a status at once: the outcome on the wire is `RETRACT`,
    and what lands in the store is an ordinary superseding version whose status is `RETRACTED`.
    The belief it withdraws is not deleted or rewritten — that is the whole difference between
    retracting a belief and pretending it was never held.
    """
    store = a_store()
    commit(store, [a_flagging_evidence()])

    withdrawn = retract(
        store, [a_fortnight_later("verified_system_observation", "ev-140")], FORTNIGHT
    )

    assert (withdrawn.outcome, withdrawn.reason) == ("RETRACT", "ABOVE_THRESHOLD")
    stored = store.collections[VERSIONS]["2"]
    assert stored["status"] == policy.RETRACTED
    assert stored["supersedes"] == 1
    assert stored["evidence"] == ["ev-118", "ev-140"], "nothing subtracts (ADR-017, ADR-018)"
    assert store.collections[VERSIONS]["1"]["status"] == STATUS, "v1 is the reasoning trail"
    span = [s for s in spans.get_finished_spans() if s.name == telemetry.SPAN_BELIEF_COMMIT][-1]
    assert span.attributes is not None
    assert span.attributes["provenance.decision.outcome"] == "RETRACT"


def test_a_retraction_is_measured_on_the_disproving_evidence_alone() -> None:
    """§6.4's door is 0.50 over the case *against* the belief — not over the accumulated set.

    Over the accumulated set any threshold would be free: that set has already cleared one.
    One fresh `verified_system_observation` is exactly 0.60, which is what makes §6.4's "at
    least as strong" bullet reachable by a single item, as it is written to be.
    """
    store = a_store()
    commit(store, [a_flagging_evidence()])

    withdrawn = retract(
        store, [a_fortnight_later("verified_system_observation", "ev-140")], FORTNIGHT
    )

    assert withdrawn.confidence == pytest.approx(0.60), "the disproving item alone, undecayed"
    assert store.collections[VERSIONS]["2"]["threshold"] == pytest.approx(0.50)


def test_a_weaker_source_class_cannot_retract(spans: InMemorySpanExporter) -> None:
    """ARCHITECTURE §10's retraction row, the refusal half.

    `agent_inference` is 0.15 against a belief established by `contractual_record` at 0.50, so
    it fails §6.4's class test — and it fails the number too, which is the point of putting the
    door at 0.50: a poisoner is stopped by both rules rather than one.
    """
    store = a_store()
    commit(store, [a_flagging_evidence()])

    refused = retract(store, [a_fortnight_later("agent_inference", "ev-140")], FORTNIGHT)

    assert refused.outcome == "REJECT"
    assert refused.reason in ("BELOW_THRESHOLD", "RETRACTION_UNSUPPORTED")
    assert "2" not in store.collections[VERSIONS], "a refused retraction wrote a version"


def test_a_strong_enough_number_still_fails_the_class_test() -> None:
    """The two rules are separate, and this is the case that proves the class test is live.

    `third_party_audit` is 0.55 — over the 0.50 door, so the number does not stop it — but the
    belief in force rests on a `verified_system_observation` at 0.60. §6.4 asks for a class at
    least as strong as the one that established the belief, and 0.55 is not.
    """
    store = a_store()
    commit(store)  # established by verified_system_observation, 0.60

    refused = retract(store, [a_fortnight_later("third_party_audit", "ev-140")], FORTNIGHT)

    assert (refused.outcome, refused.reason) == ("REJECT", "RETRACTION_UNSUPPORTED")
    assert refused.confidence > policy.NEW_BELIEF_THRESHOLD, "the number was never the obstacle"
    assert "2" not in store.collections[VERSIONS]


def test_the_same_source_class_may_retract_its_own_belief() -> None:
    """§6.4 permits exactly what §6.3 forbids, and §6.3 hands this case over deliberately.

    "A single sensor cannot both set and clear an alarm" is §6.3's rule for a *flip*. A sensor
    reporting that what it previously reported was wrong is the case §6.4 exists for, so the
    different-class rule must not apply here — if it did, a belief could only ever be retracted
    by something that had never observed it.
    """
    store = a_store()
    commit(store)

    withdrawn = retract(
        store, [a_fortnight_later("verified_system_observation", "ev-140")], FORTNIGHT
    )

    assert (withdrawn.outcome, withdrawn.reason) == ("RETRACT", "ABOVE_THRESHOLD")


def test_a_belief_cannot_be_retracted_by_its_own_evidence() -> None:
    """Stage 3 applies unchanged. Re-citing what established a belief is not a case against it."""
    store = a_store()
    commit(store)

    refused = retract(store, [an_evidence()], LATER)

    assert (refused.outcome, refused.reason) == ("REJECT", "NO_NEW_EVIDENCE")
    assert "2" not in store.collections[VERSIONS]


def test_retracting_a_belief_that_does_not_exist_is_refused() -> None:
    store = a_store()

    refused = retract(store)

    assert (refused.outcome, refused.reason) == ("REJECT", "NOTHING_TO_RETRACT")
    assert VERSIONS not in store.collections, "nothing was written, not even a collection"


def test_retracting_an_already_retracted_belief_is_refused() -> None:
    store = a_store()
    commit(store)
    retract(store, [a_fortnight_later("verified_system_observation", "ev-140")], FORTNIGHT)

    again = retract(
        store,
        [
            a_fortnight_later(
                "verified_system_observation", "ev-141", at=FORTNIGHT + timedelta(days=1)
            )
        ],
        FORTNIGHT + timedelta(days=1),
    )

    assert (again.outcome, again.reason) == ("REJECT", "NOTHING_TO_RETRACT")
    assert "3" not in store.collections[VERSIONS]


def test_a_retraction_the_agent_caused_costs_it_standing_but_an_empty_one_does_not() -> None:
    """§3.4 counts refusals "lacking verifiable evidence" — a claim, not a bookkeeping error."""
    store = a_store()
    commit(store)
    retract(store, [a_fortnight_later("third_party_audit", "ev-140")], FORTNIGHT)
    assert [entry["reason"] for entry in window(store)] == ["RETRACTION_UNSUPPORTED"]

    other = FakeFirestore(
        {"sre-infra-agent": store.docs["sre-infra-agent"]}, beliefs={}, authorizations={}
    )
    other.collections["agents"] = other.docs
    asyncio.run(
        policy.retract(
            entity="never-heard-of-it",
            domain=DOMAIN,
            evidence=[an_evidence()],
            agent_id="sre-infra-agent",
            now=NOW,
            client=other,
        )
    )

    assert [entry["reason"] for entry in window(other)] == ["RETRACTION_UNSUPPORTED"], (
        "NOTHING_TO_RETRACT is about the store's state, not the agent's evidence"
    )


# --- §6.4's third bullet: the audit ledger ------------------------------------------------------


def test_a_retraction_flags_every_action_that_rested_on_the_belief() -> None:
    """ARCHITECTURE §10's retraction row, end to end and offline.

    Two authorized actions, one of which rested on this belief. The retraction marks that one
    for review and leaves the other alone — "every action authorized on it" is a much narrower
    claim than "every action", and the control record is what keeps it narrow.
    """
    store = a_store()
    commit(store, [a_flagging_evidence()])
    ours = an_authorization(store, signature="ecdsa:aaaa", belief_ids=(BELIEF_ID,))
    theirs = an_authorization(store, signature="ecdsa:bbbb", belief_ids=("belief-pricing-api",))

    retract(store, [a_fortnight_later("verified_system_observation", "ev-140")], FORTNIGHT)

    ledger = store.collections["authorizations"]
    assert ledger[ours]["flagged_by"] == [
        {
            "belief_id": BELIEF_ID,
            "version": 1,
            "flagged_at": FORTNIGHT.strftime(audit.TIMESTAMP),
        }
    ], "the action that rested on the retracted belief is flagged for review"
    assert ledger[theirs]["flagged_by"] == [], "an unrelated action must never be flagged"


def test_a_refused_retraction_flags_nothing() -> None:
    """The flag is a consequence of retracting, not of proposing to."""
    store = a_store()
    commit(store)
    ours = an_authorization(store, signature="ecdsa:aaaa", belief_ids=(BELIEF_ID,))

    refused = retract(store, [a_fortnight_later("third_party_audit", "ev-140")], FORTNIGHT)

    assert refused.outcome == "REJECT"
    assert store.collections["authorizations"][ours]["flagged_by"] == []


def test_a_ledger_that_cannot_be_flagged_refuses_the_retraction() -> None:
    """§7.3 fail-closed, and the reason the flag is written before the version.

    A retraction whose actions were never flagged is a decision resting on a wrong thing that
    nobody knows about — the exact failure §6.4 exists to prevent. So an unwritable ledger is a
    refusal with no version appended, never a quiet success.
    """
    store = a_store()
    commit(store, [a_flagging_evidence()])
    an_authorization(store, signature="ecdsa:aaaa", belief_ids=(BELIEF_ID,))

    class _FlagFails(FakeFirestore):
        def collection(self, name: str) -> Any:
            if name == audit.COLLECTION:
                raise ServiceUnavailable("firestore is down")
            return super().collection(name)

    broken = _FlagFails(store.docs)
    broken.collections = store.collections  # every collection but the ledger works as before

    refused = retract(
        broken, [a_fortnight_later("verified_system_observation", "ev-140")], FORTNIGHT
    )

    assert (refused.outcome, refused.reason) == ("REJECT", "STORE_UNAVAILABLE")
    assert "2" not in store.collections[VERSIONS], "the version was appended anyway"


def test_a_retracted_belief_can_be_re_asserted_only_as_an_ordinary_flip() -> None:
    """Retraction is not terminal, and re-asserting is not free.

    The chain is only ever extended, so a version after a `RETRACTED` one faces §6.3's flip
    rules against everything the belief has ever rested on: 0.70 and a class the accumulated
    set does not carry. Repeating the class that retracted it is refused.
    """
    store = a_store()
    commit(store, [a_flagging_evidence()])
    retract(store, [a_fortnight_later("verified_system_observation", "ev-140")], FORTNIGHT)

    later = FORTNIGHT + timedelta(hours=1)
    repeat = commit(
        store,
        [a_fortnight_later("verified_system_observation", "ev-141", at=later)],
        status=STATUS,
        now=later,
    )
    assert (repeat.outcome, repeat.reason) == ("REJECT", "FLIP_UNSUPPORTED")

    fresh = commit(
        store,
        [a_fortnight_later("third_party_audit", "ev-142", at=later)],
        status=STATUS,
        now=later,
    )
    assert (fresh.outcome, fresh.reason) == ("COMMIT", "ABOVE_THRESHOLD")
    assert store.collections[VERSIONS]["3"]["status"] == STATUS
