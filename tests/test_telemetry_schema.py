"""The trace schema is a contract (ROADMAP item 2): these tests are what makes it one.

Everything here runs against an in-memory exporter — no GCP credentials, so CI gates on
it. The Cloud Trace half of the item's `verify:` line lives in `scripts/emit_trace_samples.py`.

Attribute keys are written out as literal strings on purpose. Asserting against the
module's own constants would pass a rename straight through; the point is to catch one.
"""

from __future__ import annotations

from collections.abc import Iterator, Sequence

import pytest
from conftest import attach_exporter
from opentelemetry.sdk.trace import ReadableSpan
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter
from opentelemetry.trace import StatusCode

from provenance import telemetry

# The provider is global and set once, in conftest.py: two modules emit spans and the second
# set_tracer_provider() would be ignored.
_EXPORTER = attach_exporter()


@pytest.fixture
def spans() -> Iterator[InMemorySpanExporter]:
    _EXPORTER.clear()
    yield _EXPORTER
    _EXPORTER.clear()


def _only(exporter: InMemorySpanExporter) -> ReadableSpan:
    finished = exporter.get_finished_spans()
    assert len(finished) == 1
    return finished[0]


def _keys(span: ReadableSpan) -> set[str]:
    assert span.attributes is not None
    return set(span.attributes)


# --- emitters used by several tests ---------------------------------------------------


def _emit_authorization() -> None:
    """The ROLLBACK_CONFIG worked example from ARCHITECTURE §4.2 — risk 2, auto-approved."""
    with telemetry.authorization_decision(
        agent_id="sre-agent",
        agent_version="v1",
        standing="GOOD",
        action_class="ROLLBACK_CONFIG",
        target="inventory-api",
        target_tier="tier2",
        blast_radius="single-service",
        reversible=True,
        evidence_ids=["ev-118"],
    ) as rec:
        rec.set_risk(base=1, criticality=1, blast=0, irreversibility=0, score=2)
        rec.set_outcome(
            outcome="APPROVE", stage="risk", reason="RISK_THRESHOLD", signature="ecdsa:x"
        )


def _emit_belief() -> None:
    with telemetry.belief_commit(
        agent_id="supply-chain-agent",
        agent_version="v3",
        standing="GOOD",
        belief_id="belief-42",
        belief_version=42,
        scope="ENTITY",
        domain="supply_chain",
        entity="SUP-042",
        status="AT_RISK",
        confidence=0.94,
        threshold=0.70,
        evidence_ids=["ev-118", "ev-140"],
        source_classes=["verified_system_observation", "third_party_audit"],
        novel_count=2,
        supersedes="belief-17",
    ) as rec:
        rec.set_outcome(outcome="COMMIT", reason="ABOVE_THRESHOLD", signature="ecdsa:y")


def _emit_verification() -> None:
    with telemetry.verification_outcome(
        predicate_id="pred-7",
        model="gemini-3.5-flash",
        action_class="ROLLBACK_CONFIG",
        target="inventory-api",
        attempt=1,
    ) as rec:
        rec.set_outcome(outcome="CONFIRMED", belief_written=True)


def _emit_reasoning() -> None:
    with telemetry.reasoning_chain(
        agent_id="sre-agent",
        agent_version="v1",
        model="gemini-2.5-pro",
        step="diagnosis",
        recall_belief_ids=["belief-42"],
    ) as rec:
        rec.set_result(
            hypotheses_considered=3,
            selected_hypothesis="config_regression",
            input_tokens=1840,
            output_tokens=220,
        )


ALL_EMITTERS = (_emit_authorization, _emit_belief, _emit_verification, _emit_reasoning)


# --- one test per shape ---------------------------------------------------------------


def test_authorization_decision_shape(spans: InMemorySpanExporter) -> None:
    _emit_authorization()
    span = _only(spans)
    assert span.name == "provenance.authorization.decision"
    assert _keys(span) == {
        "provenance.agent.id",
        "provenance.agent.version",
        "provenance.agent.standing",
        "provenance.action.class",
        "provenance.action.target",
        "provenance.action.tier",
        "provenance.action.blast_radius",
        "provenance.action.reversible",
        "provenance.action.evidence_ids",
        "provenance.risk.base",
        "provenance.risk.criticality",
        "provenance.risk.blast",
        "provenance.risk.irreversibility",
        "provenance.risk.score",
        "provenance.decision.outcome",
        "provenance.decision.stage",
        "provenance.decision.reason",
        "provenance.decision.signature",
    }
    assert span.attributes is not None
    assert span.attributes["provenance.risk.score"] == 2


def test_a_denial_before_the_registry_read_still_emits_a_span(spans: InMemorySpanExporter) -> None:
    """§2.1 stage 6: "every outcome ... including denials" -- even the earliest ones (item 7).

    A proposal rejected at schema validation has no validated action; one rejected because
    Firestore was unreachable has no standing. Both must still reach the audit stream, so
    everything but the agent identity off the presented credential is optional. Absent
    fields are omitted, not emitted empty -- a span carrying `standing: ""` would read as a
    standing that was read and found blank.
    """
    with telemetry.authorization_decision(
        agent_id="remediation-planner",
        agent_version="v1",
    ) as rec:
        rec.set_outcome(
            outcome="DENY",
            stage="registry",
            reason="REGISTRY_UNAVAILABLE",
            signature="ecdsa:z",
        )
    span = _only(spans)
    assert span.name == "provenance.authorization.decision"
    assert _keys(span) == {
        "provenance.agent.id",
        "provenance.agent.version",
        "provenance.decision.outcome",
        "provenance.decision.stage",
        "provenance.decision.reason",
        "provenance.decision.signature",
    }
    assert span.status.status_code is StatusCode.ERROR


def test_an_out_of_vocabulary_value_still_raises_when_the_field_is_optional() -> None:
    # Optional means "may be absent", never "may be anything". Widening the shape must not
    # have widened the vocabulary with it.
    with (
        pytest.raises(ValueError, match="provenance.agent.standing"),
        telemetry.authorization_decision(
            agent_id="remediation-planner",
            agent_version="v1",
            standing="PROBATION",  # type: ignore[arg-type]
        ),
    ):
        pass


def test_belief_commit_shape(spans: InMemorySpanExporter) -> None:
    _emit_belief()
    span = _only(spans)
    assert span.name == "provenance.belief.commit"
    assert _keys(span) == {
        "provenance.agent.id",
        "provenance.agent.version",
        "provenance.agent.standing",
        "provenance.belief.id",
        "provenance.belief.version",
        "provenance.belief.scope",
        "provenance.belief.domain",
        "provenance.belief.entity",
        "provenance.belief.status",
        "provenance.belief.confidence",
        "provenance.belief.threshold",
        "provenance.belief.supersedes",
        "provenance.evidence.ids",
        "provenance.evidence.source_classes",
        "provenance.evidence.novel_count",
        "provenance.decision.outcome",
        "provenance.decision.reason",
        "provenance.decision.signature",
    }


def test_verification_outcome_shape(spans: InMemorySpanExporter) -> None:
    _emit_verification()
    span = _only(spans)
    assert span.name == "provenance.verification.outcome"
    assert _keys(span) == {
        "provenance.verification.predicate_id",
        "provenance.verification.model",
        "provenance.verification.attempt",
        "provenance.verification.outcome",
        "provenance.verification.belief_written",
        "provenance.action.class",
        "provenance.action.target",
    }


def test_reasoning_chain_shape(spans: InMemorySpanExporter) -> None:
    _emit_reasoning()
    span = _only(spans)
    assert span.name == "provenance.reasoning.chain"
    assert _keys(span) == {
        "provenance.agent.id",
        "provenance.agent.version",
        "provenance.reasoning.model",
        "provenance.reasoning.step",
        "provenance.reasoning.hypotheses_considered",
        "provenance.reasoning.selected_hypothesis",
        "provenance.reasoning.input_tokens",
        "provenance.reasoning.output_tokens",
        "provenance.recall.belief_ids",
    }


def test_first_belief_omits_supersedes(spans: InMemorySpanExporter) -> None:
    """An absent optional is left off the span, not written as a None or empty string."""
    with telemetry.belief_commit(
        agent_id="a",
        agent_version="v1",
        standing="GOOD",
        belief_id="belief-1",
        belief_version=1,
        scope="ENTITY",
        domain="sre",
        entity="inventory-api",
        status="HEALTHY",
        confidence=0.60,
        threshold=0.50,
        evidence_ids=["ev-1"],
        source_classes=["verified_system_observation"],
        novel_count=1,
    ) as rec:
        rec.set_outcome(outcome="COMMIT", reason="ABOVE_THRESHOLD", signature="ecdsa:z")
    assert "provenance.belief.supersedes" not in _keys(_only(spans))


# --- fail closed ----------------------------------------------------------------------


def test_out_of_vocabulary_value_raises(spans: InMemorySpanExporter) -> None:
    with (
        pytest.raises(ValueError, match="tier4"),
        telemetry.authorization_decision(
            agent_id="a",
            agent_version="v1",
            standing="GOOD",
            action_class="ROLLBACK_CONFIG",
            target="inventory-api",
            target_tier="tier4",  # type: ignore[arg-type]
            blast_radius="single-service",
            reversible=True,
            evidence_ids=[],
        ),
    ):
        pass


def test_outcome_vocabulary_is_enforced_at_emit(spans: InMemorySpanExporter) -> None:
    with (
        pytest.raises(ValueError, match="MAYBE"),
        telemetry.verification_outcome(
            predicate_id="p",
            model="m",
            action_class="ROLLBACK_CONFIG",
            target="inventory-api",
            attempt=1,
        ) as rec,
    ):
        rec.set_outcome(outcome="MAYBE", belief_written=False)  # type: ignore[arg-type]


def test_risk_score_must_equal_its_components(spans: InMemorySpanExporter) -> None:
    """The ledger and the approval card render this arithmetic; it has to add up."""
    with (
        pytest.raises(ValueError, match="does not equal its components"),
        telemetry.authorization_decision(
            agent_id="a",
            agent_version="v1",
            standing="GOOD",
            action_class="DISABLE_COMPLIANCE_CHECKS",
            target="SUP-042",
            target_tier="tier1",
            blast_radius="org-wide",
            reversible=False,
            evidence_ids=[],
        ) as rec,
    ):
        rec.set_risk(base=4, criticality=2, blast=2, irreversibility=3, score=2)


def test_span_without_an_outcome_is_an_error(spans: InMemorySpanExporter) -> None:
    with telemetry.authorization_decision(
        agent_id="a",
        agent_version="v1",
        standing="GOOD",
        action_class="ROLLBACK_CONFIG",
        target="inventory-api",
        target_tier="tier2",
        blast_radius="single-service",
        reversible=True,
        evidence_ids=[],
    ):
        pass
    span = _only(spans)
    assert span.status.status_code is StatusCode.ERROR
    assert span.status.description == "outcome never recorded"


@pytest.mark.parametrize(
    ("outcome", "expected"),
    [("CONFIRMED", StatusCode.OK), ("REFUTED", StatusCode.ERROR), ("INCONCLUSIVE", StatusCode.OK)],
)
def test_only_refutation_is_an_error_status(
    spans: InMemorySpanExporter, outcome: telemetry.VerificationOutcome, expected: StatusCode
) -> None:
    """INCONCLUSIVE is an honest result (§7.2), not a failure of the run."""
    with telemetry.verification_outcome(
        predicate_id="p",
        model="m",
        action_class="ROLLBACK_CONFIG",
        target="inventory-api",
        attempt=1,
    ) as rec:
        rec.set_outcome(outcome=outcome, belief_written=outcome == "CONFIRMED")
    assert _only(spans).status.status_code is expected


def test_denial_is_an_error_status(spans: InMemorySpanExporter) -> None:
    with telemetry.authorization_decision(
        agent_id="a",
        agent_version="v1",
        standing="SUSPENDED",
        action_class="ROLLBACK_CONFIG",
        target="inventory-api",
        target_tier="tier2",
        blast_radius="single-service",
        reversible=True,
        evidence_ids=[],
    ) as rec:
        rec.set_outcome(
            outcome="DENY", stage="registry", reason="STANDING_SUSPENDED", signature="ecdsa:q"
        )
    span = _only(spans)
    assert span.status.status_code is StatusCode.ERROR
    assert "provenance.risk.score" not in _keys(span)  # terminated before the risk stage


# --- trace IDs and redaction ----------------------------------------------------------


def test_nested_shapes_share_one_trace_id(spans: InMemorySpanExporter) -> None:
    """The half of item 2's `verify:` line that is provable without Cloud Trace."""
    with telemetry.reasoning_chain(
        agent_id="sre-agent",
        agent_version="v1",
        model="gemini-2.5-pro",
        step="diagnosis",
        recall_belief_ids=[],
    ) as outer:
        _emit_authorization()
        outer.set_result(
            hypotheses_considered=1,
            selected_hypothesis="config_regression",
            input_tokens=1,
            output_tokens=1,
        )
    inner, outer_span = spans.get_finished_spans()
    assert inner.context is not None and outer_span.context is not None
    assert inner.context.trace_id == outer_span.context.trace_id
    assert inner.parent is not None
    assert inner.parent.span_id == outer_span.context.span_id


_FORBIDDEN_KEY_PARTS = ("prompt", "rationale", "payload", "text", "content", "message", "body")
_ALLOWED_TYPES = (str, int, float, bool)


def test_no_shape_carries_content(spans: InMemorySpanExporter) -> None:
    """IDs, hashes, enums and numbers only — the module's stated contract, and what item
    26's "raw inbound text never appears in the trace" is checked against."""
    for emit in ALL_EMITTERS:
        emit()
    for span in spans.get_finished_spans():
        assert span.attributes is not None
        for key, value in span.attributes.items():
            assert not any(part in key for part in _FORBIDDEN_KEY_PARTS), key
            if isinstance(value, Sequence) and not isinstance(value, str):
                assert all(isinstance(item, _ALLOWED_TYPES) for item in value), key
            else:
                assert isinstance(value, _ALLOWED_TYPES), key


# --- setup ----------------------------------------------------------------------------


def test_configure_tracing_is_a_noop_without_a_project(monkeypatch: pytest.MonkeyPatch) -> None:
    """CI has no credentials; emitting must stay safe rather than needing a guard."""
    monkeypatch.delenv("GOOGLE_CLOUD_PROJECT", raising=False)
    assert telemetry.configure_tracing() is False
