"""ROADMAP item 9's offline half: the control loop, against a fake model.

The `verify:` line -- "the injected `inventory-api` error-rate spike produces exactly one
typed `ROLLBACK_CONFIG` proposal, risk 2, auto-approved" -- is proved live against real
Gemini by `scripts/verify_incident_one.py`. What is proved here is everything the live run
cannot check honestly because a real model would have to cooperate: that a malformed
emission is returned exactly once and escalates on the second (§7.1), that an unroutable
classification ends the incident instead of guessing, and that a Planner understating a
tier is rejected before the gateway rather than scored.

The fake model is the same idea as `tests/test_registry.py`'s `FakeFirestore`: the point of
these tests is a *sequence* of emissions, and only a model whose next reply is known can
express one.
"""

from __future__ import annotations

import asyncio
import json
from collections.abc import AsyncGenerator
from dataclasses import replace
from typing import Any

import pytest
from conftest import attach_exporter
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from google.adk.models.base_llm import BaseLlm
from google.adk.models.llm_request import LlmRequest
from google.adk.models.llm_response import LlmResponse
from google.genai import types
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter
from pydantic import Field
from test_registry import FakeFirestore

from provenance import incident, registry, telemetry

_EXPORTER = attach_exporter()

PLANNER_KEY = ec.generate_private_key(ec.SECP256R1())
PLANNER_PEM = (
    PLANNER_KEY.public_key()
    .public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
    .decode()
)


@pytest.fixture
def spans() -> Any:
    _EXPORTER.clear()
    yield _EXPORTER
    _EXPORTER.clear()


# --- the fake model -----------------------------------------------------------------------


class FakeLlm(BaseLlm):
    """Replies in order from a queue. Records the prompts it was given, for the re-plan test."""

    replies: list[str] = Field(default_factory=list)
    prompts: list[str] = Field(default_factory=list)

    async def generate_content_async(
        self, llm_request: LlmRequest, stream: bool = False
    ) -> AsyncGenerator[LlmResponse, None]:
        self.prompts.append(str(llm_request.config.system_instruction))
        yield LlmResponse(
            content=types.Content(role="model", parts=[types.Part(text=self.replies.pop(0))]),
            usage_metadata=types.GenerateContentResponseUsageMetadata(
                prompt_token_count=1200, candidates_token_count=90
            ),
        )


def a_store(**overrides: Any) -> FakeFirestore:
    record = registry.Agent(
        id="remediation-planner",
        version="v3",
        public_key=PLANNER_PEM,
        tool_scope=("ROLLBACK_CONFIG", "DISABLE_COMPLIANCE_CHECKS"),
        memory_domains=(),
        standing="GOOD",
        rejection_window=(),
    )
    return FakeFirestore(
        {"remediation-planner": registry.to_document(replace(record, **overrides))}
    )


def a_trigger(**overrides: Any) -> incident.Trigger:
    """The spec's §13 incident #1: inventory-api's error rate spikes to 38%."""
    return replace(
        incident.Trigger(
            target="inventory-api",
            signal="error_rate",
            observed_value=0.38,
            observed_at="2026-08-21T14:06:00Z",
        ),
        **overrides,
    )


def a_classification(domain: str = "infrastructure") -> str:
    return json.dumps(
        {"domain": domain, "hypotheses_considered": 2, "selected_hypothesis": "infra_fault"}
    )


def a_diagnosis() -> str:
    return json.dumps(
        {
            "summary": "Error rate rose after v42 was deployed over known-good v41.",
            "evidence_refs": ["obs-error-rate", "obs-config-deploy"],
            "recommended_action_class": "ROLLBACK_CONFIG",
            "hypotheses_considered": 3,
            "selected_hypothesis": "config_regression",
        }
    )


def a_proposal(**overrides: Any) -> str:
    return json.dumps(
        {
            "action_class": "ROLLBACK_CONFIG",
            "target": "inventory-api",
            "target_tier": "tier2",
            "blast_radius": "single-service",
            "reversible": True,
            "evidence_refs": ["obs-error-rate"],
            "success_predicate": "error_rate on inventory-api falls below 0.05 within 10m",
            "proposed_by": "remediation-planner@v3",
            "hypotheses_considered": 2,
            "selected_hypothesis": "rollback_to_known_good",
        }
        | overrides
    )


def run(replies: list[str], *, store: FakeFirestore | None = None) -> incident.IncidentResult:
    """One incident, with every model call answered from `replies` in order."""
    model = FakeLlm(model="fake-model", replies=list(replies), prompts=[])
    return asyncio.run(
        incident.run_incident(
            a_trigger(),
            client=store if store is not None else a_store(),
            planner_key=PLANNER_KEY,
            model_orchestrator=model,
            model_domain=model,
            model_planner=model,
        )
    )


# --- the happy path -----------------------------------------------------------------------


def test_one_trigger_produces_one_rollback_proposal_scoring_2_and_auto_approved(
    spans: InMemorySpanExporter,
) -> None:
    """Item 9's `verify:` line, with the model's cooperation stipulated rather than hoped for."""
    result = run([a_classification(), a_diagnosis(), a_proposal()])

    assert result.outcome == "AUTHORIZED"
    assert result.action is not None
    assert (result.action.action_class, result.action.target) == (
        "ROLLBACK_CONFIG",
        "inventory-api",
    )
    assert result.decision is not None
    assert result.decision.outcome == "APPROVE"
    assert result.decision.stage == "risk"
    assert result.decision.score is not None
    assert result.decision.score.score == 2
    assert result.malformed_attempts == 0


def test_the_incident_span_is_the_root_and_carries_the_predicate(
    spans: InMemorySpanExporter,
) -> None:
    result = run([a_classification(), a_diagnosis(), a_proposal()])
    finished = spans.get_finished_spans()
    root = next(s for s in finished if s.name == telemetry.SPAN_INCIDENT)

    assert root.parent is None
    assert root.attributes is not None
    assert root.attributes["provenance.incident.outcome"] == "AUTHORIZED"
    assert root.attributes["provenance.incident.routed_to"] == "sre-infra-agent"
    assert result.action is not None
    from provenance import action as action_module

    assert root.attributes["provenance.incident.predicate_id"] == action_module.predicate_id(
        result.action
    )
    # Every other span in the incident hangs off it: one trace, item 2's contract.
    assert root.context is not None
    assert all(
        s.context is not None and s.context.trace_id == root.context.trace_id for s in finished
    )


def test_each_reasoning_step_emits_one_chain_span(spans: InMemorySpanExporter) -> None:
    """Item 2 defined `reasoning.chain` and shipped it with no emitter. This is the first."""
    run([a_classification(), a_diagnosis(), a_proposal()])
    chains = [s for s in spans.get_finished_spans() if s.name == telemetry.SPAN_REASONING_CHAIN]
    assert [s.attributes["provenance.reasoning.step"] for s in chains if s.attributes] == [
        "classification",
        "diagnosis",
        "planning",
    ]
    # Who reasoned, not who may act: the Orchestrator holds no registry record.
    assert chains[0].attributes is not None
    assert chains[0].attributes["provenance.agent.id"] == "orchestrator"
    assert chains[2].attributes is not None
    assert chains[2].attributes["provenance.agent.version"] == "v3"
    assert chains[2].attributes["provenance.reasoning.input_tokens"] == 1200


# --- §7.1: the control loop owns the count ------------------------------------------------


def test_a_malformed_emission_is_returned_once_and_the_replan_is_authorized(
    spans: InMemorySpanExporter,
) -> None:
    """§7.1: "rejected mechanically and returned to the Planner exactly once"."""
    result = run(
        [
            a_classification(),
            a_diagnosis(),
            a_proposal(action_class="RESTART_EVERYTHING"),
            a_proposal(),
        ]
    )
    assert result.malformed_attempts == 1
    assert result.outcome == "AUTHORIZED"
    assert result.decision is not None and result.decision.score is not None
    assert result.decision.score.score == 2


def test_a_second_malformed_emission_escalates_and_never_reaches_the_gateway(
    spans: InMemorySpanExporter,
) -> None:
    """`MALFORMED_RETRY_BUDGET` is 1, so the third emission never happens."""
    replies = [
        a_classification(),
        a_diagnosis(),
        a_proposal(action_class="RESTART_EVERYTHING"),
        a_proposal(target="no-such-service"),
        a_proposal(),  # must never be consumed
    ]
    model = FakeLlm(model="fake-model", replies=list(replies), prompts=[])
    result = asyncio.run(
        incident.run_incident(
            a_trigger(),
            client=a_store(),
            planner_key=PLANNER_KEY,
            model_orchestrator=model,
            model_domain=model,
            model_planner=model,
        )
    )
    assert result.outcome == "ESCALATED"
    assert result.malformed_attempts == 2
    assert result.decision is None
    assert model.replies == [a_proposal()], "the loop asked the Planner a third time"
    assert not [
        s for s in spans.get_finished_spans() if s.name == telemetry.SPAN_AUTHORIZATION_DECISION
    ]


def test_the_replan_prompt_carries_the_rejection_reason(spans: InMemorySpanExporter) -> None:
    """A re-plan with no feedback is just a second roll of the dice."""
    model = FakeLlm(
        model="fake-model",
        replies=[
            a_classification(),
            a_diagnosis(),
            a_proposal(action_class="RESTART_EVERYTHING"),
            a_proposal(),
        ],
        prompts=[],
    )
    asyncio.run(
        incident.run_incident(
            a_trigger(),
            client=a_store(),
            planner_key=PLANNER_KEY,
            model_orchestrator=model,
            model_domain=model,
            model_planner=model,
        )
    )
    assert "RESTART_EVERYTHING" in model.prompts[-1]


# --- routing ------------------------------------------------------------------------------


def test_an_unclassifiable_incident_is_unroutable_rather_than_guessed(
    spans: InMemorySpanExporter,
) -> None:
    result = run([a_classification(domain="quantum-astrology")])
    assert result.outcome == "UNROUTABLE"
    assert result.decision is None and result.action is None
    root = next(s for s in spans.get_finished_spans() if s.name == telemetry.SPAN_INCIDENT)
    assert root.attributes is not None
    assert "provenance.incident.routed_to" not in root.attributes


# --- the determinism boundary -------------------------------------------------------------


def test_a_planner_understating_the_tier_is_rejected_before_the_gateway(
    spans: InMemorySpanExporter,
) -> None:
    """Understating tier2 as tier3 is worth -1 on the score. It never gets to be scored.

    This is the one test that would still matter if every other guarantee held: it is the
    whole reason a model's declared fields are checked against an authority (§3.1, item 6).
    """
    result = run(
        [
            a_classification(),
            a_diagnosis(),
            a_proposal(target_tier="tier3"),
            a_proposal(target_tier="tier3"),
        ]
    )
    assert result.outcome == "ESCALATED"
    assert result.malformed_attempts == 2
    assert not [
        s for s in spans.get_finished_spans() if s.name == telemetry.SPAN_AUTHORIZATION_DECISION
    ]


def test_a_degraded_planner_is_held_carrying_the_same_score(spans: InMemorySpanExporter) -> None:
    """§3.4's "held regardless of risk score", reached through the whole loop for once."""
    result = run(
        [a_classification(), a_diagnosis(), a_proposal()], store=a_store(standing="DEGRADED")
    )
    assert result.outcome == "HELD"
    assert result.decision is not None
    assert result.decision.reason == "STANDING_DEGRADED"
    assert result.decision.score is not None and result.decision.score.score == 2
