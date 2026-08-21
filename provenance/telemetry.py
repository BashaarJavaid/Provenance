"""The one trace stream: OpenTelemetry span shapes, defined before any agent exists.

`ARCHITECTURE.md` §8 commits every component to a single stream. The trace UI, the
gateway ledger, the audit log, and the counterfactual A/B all read *these* spans, so the
vocabulary is a contract rather than whatever each emitter happens to attach.

Four shapes, one per authority-relevant event:

| Span | Source |
|---|---|
| `provenance.authorization.decision` | the action pipeline (§2.1), risk arithmetic (§4.2) |
| `provenance.belief.commit`         | the memory write pipeline (§2.2) |
| `provenance.verification.outcome`  | three-valued verification (§7.2) |
| `provenance.reasoning.chain`       | what a model considered, structurally |

**Attributes carry identifiers, hashes, enums and numbers — never content.** No payload
text, no prompt, no model output, no rationale prose. Evidence appears as IDs and source
classes; what an evidence item *said* stays out of the stream. This is what makes item
26's "raw inbound text never appears in the trace" checkable rather than aspirational.

Fail-closed (§7.3): required fields are typed keyword arguments, so mypy-strict catches an
omission at build time and an out-of-vocabulary value raises at emit time. A span that
exits without recording its outcome is marked ERROR — an unfinished decision must not read
as a clean one.
"""

from __future__ import annotations

import os
from collections.abc import Iterator, Sequence
from contextlib import contextmanager
from dataclasses import dataclass, field
from typing import Literal, get_args

from opentelemetry import trace
from opentelemetry.exporter.cloud_trace import CloudTraceSpanExporter
from opentelemetry.sdk.resources import SERVICE_NAME, Resource
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor
from opentelemetry.trace import Span, Status, StatusCode

# --- vocabulary -----------------------------------------------------------------------

Tier = Literal["tier1", "tier2", "tier3"]
BlastRadius = Literal["single-service", "multi-service", "org-wide"]
TargetKind = Literal["service", "supplier"]
Standing = Literal["GOOD", "DEGRADED", "SUSPENDED"]
AuthOutcome = Literal["APPROVE", "APPROVE_NOTIFY", "HOLD", "DENY"]
AuthStage = Literal["schema", "identity", "registry", "abac", "risk"]
BeliefScope = Literal["ENTITY", "CLASS"]
BeliefOutcome = Literal["COMMIT", "REJECT", "RETRACT"]
SourceClass = Literal[
    "verified_system_observation",
    "third_party_audit",
    "contractual_record",
    "agent_inference",
    "unverified_external_claim",
]
VerificationOutcome = Literal["CONFIRMED", "REFUTED", "INCONCLUSIVE"]

SPAN_AUTHORIZATION_DECISION = "provenance.authorization.decision"
SPAN_BELIEF_COMMIT = "provenance.belief.commit"
SPAN_VERIFICATION_OUTCOME = "provenance.verification.outcome"
SPAN_REASONING_CHAIN = "provenance.reasoning.chain"

ATTR_AGENT_ID = "provenance.agent.id"
ATTR_AGENT_VERSION = "provenance.agent.version"
ATTR_AGENT_STANDING = "provenance.agent.standing"

ATTR_ACTION_CLASS = "provenance.action.class"
ATTR_ACTION_TARGET = "provenance.action.target"
ATTR_ACTION_TIER = "provenance.action.tier"
ATTR_ACTION_BLAST_RADIUS = "provenance.action.blast_radius"
ATTR_ACTION_REVERSIBLE = "provenance.action.reversible"
ATTR_ACTION_EVIDENCE_IDS = "provenance.action.evidence_ids"

ATTR_RISK_BASE = "provenance.risk.base"
ATTR_RISK_CRITICALITY = "provenance.risk.criticality"
ATTR_RISK_BLAST = "provenance.risk.blast"
ATTR_RISK_IRREVERSIBILITY = "provenance.risk.irreversibility"
ATTR_RISK_SCORE = "provenance.risk.score"

ATTR_BELIEF_ID = "provenance.belief.id"
ATTR_BELIEF_VERSION = "provenance.belief.version"
ATTR_BELIEF_SCOPE = "provenance.belief.scope"
ATTR_BELIEF_DOMAIN = "provenance.belief.domain"
ATTR_BELIEF_ENTITY = "provenance.belief.entity"
ATTR_BELIEF_STATUS = "provenance.belief.status"
ATTR_BELIEF_CONFIDENCE = "provenance.belief.confidence"
ATTR_BELIEF_THRESHOLD = "provenance.belief.threshold"
ATTR_BELIEF_SUPERSEDES = "provenance.belief.supersedes"

ATTR_EVIDENCE_IDS = "provenance.evidence.ids"
ATTR_EVIDENCE_SOURCE_CLASSES = "provenance.evidence.source_classes"
ATTR_EVIDENCE_NOVEL_COUNT = "provenance.evidence.novel_count"

ATTR_VERIFICATION_OUTCOME = "provenance.verification.outcome"
ATTR_VERIFICATION_PREDICATE_ID = "provenance.verification.predicate_id"
ATTR_VERIFICATION_MODEL = "provenance.verification.model"
ATTR_VERIFICATION_ATTEMPT = "provenance.verification.attempt"
ATTR_VERIFICATION_BELIEF_WRITTEN = "provenance.verification.belief_written"

ATTR_REASONING_MODEL = "provenance.reasoning.model"
ATTR_REASONING_STEP = "provenance.reasoning.step"
ATTR_REASONING_HYPOTHESES_CONSIDERED = "provenance.reasoning.hypotheses_considered"
ATTR_REASONING_SELECTED_HYPOTHESIS = "provenance.reasoning.selected_hypothesis"
ATTR_REASONING_INPUT_TOKENS = "provenance.reasoning.input_tokens"
ATTR_REASONING_OUTPUT_TOKENS = "provenance.reasoning.output_tokens"
ATTR_RECALL_BELIEF_IDS = "provenance.recall.belief_ids"

ATTR_DECISION_OUTCOME = "provenance.decision.outcome"
ATTR_DECISION_REASON = "provenance.decision.reason"
ATTR_DECISION_STAGE = "provenance.decision.stage"
ATTR_DECISION_SIGNATURE = "provenance.decision.signature"

# Outcomes that are failures of the thing being traced, not of the tracing.
# INCONCLUSIVE is deliberately absent: ambiguity is an honest result (§7.2).
_ERROR_OUTCOMES = frozenset({"DENY", "REJECT", "REFUTED"})

_SERVICE = "provenance"

# --- setup ----------------------------------------------------------------------------


def configure_tracing(project_id: str | None = None) -> bool:
    """Export spans to Cloud Trace. Returns False (a no-op tracer) with no project set.

    Emitting is therefore always safe: CI and local runs need no credentials, and no
    call site has to guard on whether telemetry is configured.
    """
    project_id = project_id or os.environ.get("GOOGLE_CLOUD_PROJECT")
    if not project_id:
        return False
    provider = TracerProvider(resource=Resource.create({SERVICE_NAME: _SERVICE}))
    # opentelemetry-exporter-gcp-trace ships no py.typed, so its constructor reads as untyped.
    exporter = CloudTraceSpanExporter(project_id=project_id)  # type: ignore[no-untyped-call]
    provider.add_span_processor(BatchSpanProcessor(exporter))
    trace.set_tracer_provider(provider)
    return True


# --- emit helpers ---------------------------------------------------------------------


def _enum(value: str, allowed: object, attr: str) -> str:
    if value not in get_args(allowed):
        raise ValueError(f"{attr}: {value!r} is not one of {get_args(allowed)}")
    return value


def _opt_enum(value: str | None, allowed: object, attr: str) -> str | None:
    """`_enum`, but `None` passes through as "not known at this stage" (item 7).

    Only the authorization span needs this. A proposal denied at schema validation has no
    validated action fields, and one denied because the registry was unreachable has no
    standing -- but both are outcomes the audit stream must carry (§2.1 stage 6: "every
    outcome ... including denials"). `_set_attributes` already drops `None`, so the
    attribute is absent rather than present-and-empty, and an out-of-vocabulary value still
    raises.
    """
    return None if value is None else _enum(value, allowed, attr)


@dataclass
class _Recorder:
    """Base for the per-shape outcome recorders; tracks that an outcome was in fact set."""

    span: Span
    recorded: bool = field(default=False, init=False)

    def _finish(self, outcome: str, attributes: dict[str, object]) -> None:
        _set_attributes(self.span, attributes)
        if outcome in _ERROR_OUTCOMES:
            self.span.set_status(Status(StatusCode.ERROR, outcome))
        else:
            self.span.set_status(Status(StatusCode.OK))
        self.recorded = True


def _set_attributes(span: Span, attributes: dict[str, object]) -> None:
    for key, value in attributes.items():
        if value is not None:  # an absent optional (e.g. a first belief has no supersedes)
            span.set_attribute(key, value)  # type: ignore[arg-type]


@contextmanager
def _shape[R: _Recorder](
    name: str, attributes: dict[str, object], recorder: type[R]
) -> Iterator[R]:
    tracer = trace.get_tracer(_SERVICE)
    with tracer.start_as_current_span(name) as span:
        _set_attributes(span, attributes)
        rec = recorder(span)
        yield rec
        if not rec.recorded:
            # A decision that never reached an outcome is not a clean one (§7.3).
            span.set_status(Status(StatusCode.ERROR, "outcome never recorded"))


class AuthorizationRecorder(_Recorder):
    def set_risk(
        self, *, base: int, criticality: int, blast: int, irreversibility: int, score: int
    ) -> None:
        """Record the §4.2 arithmetic. Not called when an earlier stage terminates first."""
        if score != base + criticality + blast + irreversibility:
            raise ValueError(f"risk score {score} does not equal its components")
        self.span.set_attribute(ATTR_RISK_BASE, base)
        self.span.set_attribute(ATTR_RISK_CRITICALITY, criticality)
        self.span.set_attribute(ATTR_RISK_BLAST, blast)
        self.span.set_attribute(ATTR_RISK_IRREVERSIBILITY, irreversibility)
        self.span.set_attribute(ATTR_RISK_SCORE, score)

    def set_outcome(
        self, *, outcome: AuthOutcome, stage: AuthStage, reason: str, signature: str
    ) -> None:
        self._finish(
            _enum(outcome, AuthOutcome, ATTR_DECISION_OUTCOME),
            {
                ATTR_DECISION_OUTCOME: outcome,
                ATTR_DECISION_STAGE: _enum(stage, AuthStage, ATTR_DECISION_STAGE),
                ATTR_DECISION_REASON: reason,
                ATTR_DECISION_SIGNATURE: signature,
            },
        )


@contextmanager
def authorization_decision(
    *,
    agent_id: str,
    agent_version: str,
    standing: Standing | None = None,
    action_class: str | None = None,
    target: str | None = None,
    target_tier: Tier | None = None,
    blast_radius: BlastRadius | None = None,
    reversible: bool | None = None,
    evidence_ids: Sequence[str] | None = None,
) -> Iterator[AuthorizationRecorder]:
    """The §2.1 action pipeline: one span per proposal, denials included.

    Everything but the agent's id and version is optional, because §2.1's earliest stages
    terminate before those facts exist: a proposal rejected at schema validation has no
    validated action to describe, and one rejected because the registry was unreachable has
    no standing to report. Requiring them would have meant either a fifth span shape or two
    denial classes missing from the audit stream, and §2.1 stage 6 admits neither. The id
    and version stay required — they come off the presented credential, which is on every
    path. Absent fields are omitted from the span, never emitted empty.
    """
    with _shape(
        SPAN_AUTHORIZATION_DECISION,
        {
            ATTR_AGENT_ID: agent_id,
            ATTR_AGENT_VERSION: agent_version,
            ATTR_AGENT_STANDING: _opt_enum(standing, Standing, ATTR_AGENT_STANDING),
            ATTR_ACTION_CLASS: action_class,
            ATTR_ACTION_TARGET: target,
            ATTR_ACTION_TIER: _opt_enum(target_tier, Tier, ATTR_ACTION_TIER),
            ATTR_ACTION_BLAST_RADIUS: _opt_enum(
                blast_radius, BlastRadius, ATTR_ACTION_BLAST_RADIUS
            ),
            ATTR_ACTION_REVERSIBLE: reversible,
            ATTR_ACTION_EVIDENCE_IDS: None if evidence_ids is None else tuple(evidence_ids),
        },
        AuthorizationRecorder,
    ) as rec:
        yield rec


class BeliefRecorder(_Recorder):
    def set_outcome(self, *, outcome: BeliefOutcome, reason: str, signature: str) -> None:
        self._finish(
            _enum(outcome, BeliefOutcome, ATTR_DECISION_OUTCOME),
            {
                ATTR_DECISION_OUTCOME: outcome,
                ATTR_DECISION_REASON: reason,
                ATTR_DECISION_SIGNATURE: signature,
            },
        )


@contextmanager
def belief_commit(
    *,
    agent_id: str,
    agent_version: str,
    standing: Standing,
    belief_id: str,
    belief_version: int,
    scope: BeliefScope,
    domain: str,
    entity: str,
    status: str,
    confidence: float,
    threshold: float,
    evidence_ids: Sequence[str],
    source_classes: Sequence[SourceClass],
    novel_count: int,
    supersedes: str | None = None,
) -> Iterator[BeliefRecorder]:
    """The §2.2 memory write pipeline. COMMIT, REJECT and RETRACT share this shape."""
    with _shape(
        SPAN_BELIEF_COMMIT,
        {
            ATTR_AGENT_ID: agent_id,
            ATTR_AGENT_VERSION: agent_version,
            ATTR_AGENT_STANDING: _enum(standing, Standing, ATTR_AGENT_STANDING),
            ATTR_BELIEF_ID: belief_id,
            ATTR_BELIEF_VERSION: belief_version,
            ATTR_BELIEF_SCOPE: _enum(scope, BeliefScope, ATTR_BELIEF_SCOPE),
            ATTR_BELIEF_DOMAIN: domain,
            ATTR_BELIEF_ENTITY: entity,
            ATTR_BELIEF_STATUS: status,
            ATTR_BELIEF_CONFIDENCE: confidence,
            ATTR_BELIEF_THRESHOLD: threshold,
            ATTR_BELIEF_SUPERSEDES: supersedes,
            ATTR_EVIDENCE_IDS: tuple(evidence_ids),
            ATTR_EVIDENCE_SOURCE_CLASSES: tuple(
                _enum(sc, SourceClass, ATTR_EVIDENCE_SOURCE_CLASSES) for sc in source_classes
            ),
            ATTR_EVIDENCE_NOVEL_COUNT: novel_count,
        },
        BeliefRecorder,
    ) as rec:
        yield rec


class VerificationRecorder(_Recorder):
    def set_outcome(self, *, outcome: VerificationOutcome, belief_written: bool) -> None:
        self._finish(
            _enum(outcome, VerificationOutcome, ATTR_VERIFICATION_OUTCOME),
            {
                ATTR_VERIFICATION_OUTCOME: outcome,
                ATTR_VERIFICATION_BELIEF_WRITTEN: belief_written,
            },
        )


@contextmanager
def verification_outcome(
    *,
    predicate_id: str,
    model: str,
    action_class: str,
    target: str,
    attempt: int,
) -> Iterator[VerificationRecorder]:
    """Three-valued verification (§7.2). `belief_written` is how the trace shows that
    INCONCLUSIVE wrote nothing."""
    with _shape(
        SPAN_VERIFICATION_OUTCOME,
        {
            ATTR_VERIFICATION_PREDICATE_ID: predicate_id,
            ATTR_VERIFICATION_MODEL: model,
            ATTR_ACTION_CLASS: action_class,
            ATTR_ACTION_TARGET: target,
            ATTR_VERIFICATION_ATTEMPT: attempt,
        },
        VerificationRecorder,
    ) as rec:
        yield rec


class ReasoningRecorder(_Recorder):
    def set_result(
        self,
        *,
        hypotheses_considered: int,
        selected_hypothesis: str,
        input_tokens: int,
        output_tokens: int,
    ) -> None:
        """`hypotheses_considered` is the metric the item-32 counterfactual A/B reads."""
        # A reasoning chain has no decision outcome to succeed or fail at; it only completes.
        self._finish(
            "COMPLETE",
            {
                ATTR_REASONING_HYPOTHESES_CONSIDERED: hypotheses_considered,
                ATTR_REASONING_SELECTED_HYPOTHESIS: selected_hypothesis,
                ATTR_REASONING_INPUT_TOKENS: input_tokens,
                ATTR_REASONING_OUTPUT_TOKENS: output_tokens,
            },
        )


@contextmanager
def reasoning_chain(
    *,
    agent_id: str,
    agent_version: str,
    model: str,
    step: str,
    recall_belief_ids: Sequence[str],
) -> Iterator[ReasoningRecorder]:
    """What a model considered, structurally. Labels and IDs only — never its prose."""
    with _shape(
        SPAN_REASONING_CHAIN,
        {
            ATTR_AGENT_ID: agent_id,
            ATTR_AGENT_VERSION: agent_version,
            ATTR_REASONING_MODEL: model,
            ATTR_REASONING_STEP: step,
            ATTR_RECALL_BELIEF_IDS: tuple(recall_belief_ids),
        },
        ReasoningRecorder,
    ) as rec:
        yield rec
