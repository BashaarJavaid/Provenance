"""The Memory Policy Engine: the computed number, the refusals, and the superseding write.

`ARCHITECTURE.md` §10's confidence rows belong to item 13 and §6.3's conflict rule to item
14. What is checked here is only what the engine claims: §4.3's arithmetic over one source
class, the §2.2 stage-2 standing and domain checks, the threshold, the re-affirmation that
supersedes v1 (item 12), and the status flip it refuses until the rule governing one exists.

The two confidence tests are the ones that would matter if every other guarantee held. If
restating one observation twice moved the number, an agent could talk any belief over the
threshold by repeating itself — which is the poisoning attack §6.3 exists to stop, and §4.3
stops it with a `max` rather than with a model's opinion.
"""

from __future__ import annotations

import asyncio
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from conftest import attach_exporter
from google.api_core.exceptions import ServiceUnavailable
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter
from test_registry import FakeFirestore

from provenance import policy, registry, telemetry

_EXPORTER = attach_exporter()

NOW = datetime(2026, 8, 22, 12, 0, 0, tzinfo=UTC)
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

    second = commit(store, [an_evidence(id="ev-2")])

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

    flip = commit(store, [an_evidence(id="ev-2")], status="HEALTHY")

    assert (flip.outcome, flip.reason) == ("REJECT", "FLIP_UNSUPPORTED")
    assert flip.confidence == pytest.approx(0.60)
    assert flip.version == 2
    assert "2" not in store.collections[VERSIONS]
    span = [s for s in spans.get_finished_spans() if s.name == telemetry.SPAN_BELIEF_COMMIT][-1]
    assert span.attributes is not None
    assert span.attributes["provenance.belief.supersedes"] == 1


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
