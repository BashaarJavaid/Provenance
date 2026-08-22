"""The Memory Policy Engine: the computed number, the refusals, and the superseding write.

`ARCHITECTURE.md` §10's confidence and novelty rows are item 13's and §6.3's conflict rule is
item 14's. What is checked here is only what the engine claims: §4.3's arithmetic over the
accumulated evidence, the §2.2 stage-2 standing and domain checks, stage 3's mechanical
novelty check, the threshold, the re-affirmation that supersedes v1 (item 12), and the status
flip it refuses until the rule governing one exists.

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

from provenance import beliefs, policy, registry, telemetry

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
        {"sre-infra-agent": registry.to_document(replace(record, **overrides))}, beliefs={}
    )


def commit(
    store: FakeFirestore,
    evidence: list[policy.Evidence] | None = None,
    status: str = STATUS,
) -> Any:
    return asyncio.run(
        policy.commit(
            entity=ENTITY,
            domain=DOMAIN,
            status=status,
            evidence=evidence if evidence is not None else [an_evidence()],
            agent_id="sre-infra-agent",
            now=NOW,
            client=store,
        )
    )


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


def test_a_status_flip_is_refused_until_the_conflict_rule_exists(
    spans: InMemorySpanExporter,
) -> None:
    """§4.3 puts a flip behind 0.70 *plus* §6.3's different-source-class rule (item 14).

    Letting one through the 0.50 new-belief door in the meantime would mean a single sensor
    could set and clear its own alarm — the exact thing §6.3 exists to prevent. The refusal
    still carries the arithmetic, so the trace shows what was proposed and why it stopped.
    """
    store = a_store()
    commit(store)

    flip = commit(store, [a_later_evidence()], status="HEALTHY")

    assert (flip.outcome, flip.reason) == ("REJECT", "FLIP_UNSUPPORTED")
    assert flip.confidence == pytest.approx(0.60)
    assert flip.version == 2
    assert "2" not in store.collections[VERSIONS]
    span = [s for s in spans.get_finished_spans() if s.name == telemetry.SPAN_BELIEF_COMMIT][-1]
    assert span.attributes is not None
    assert span.attributes["provenance.belief.supersedes"] == 1


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
