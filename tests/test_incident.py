"""ROADMAP item 9's offline half: the control loop, against a fake model.

The `verify:` line -- "the injected `inventory-api` error-rate spike produces exactly one
typed `ROLLBACK_CONFIG` proposal, risk 2, auto-approved" -- is proved live against real
Gemini by `scripts/verify_incident_one.py`. What is proved here is everything the live run
cannot check honestly because a real model would have to cooperate: that a malformed
emission is returned exactly once and escalates on the second (§7.1), that an unroutable
classification ends the incident instead of guessing, and that a Planner understating a
tier is rejected before the gateway rather than scored.

Item 10 added the second half of the loop -- execute, verify, resolve -- and with it the
three tests a live run cannot force: an INCONCLUSIVE verification (a cooperative model will
not produce one on cue), a held incident proving it executed nothing, and an execution
failure proving §7.3's posture.

The fake model is the same idea as `tests/test_registry.py`'s `FakeFirestore`: the point of
these tests is a *sequence* of emissions, and only a model whose next reply is known can
express one.
"""

from __future__ import annotations

import asyncio
import json
from collections.abc import AsyncGenerator
from dataclasses import asdict, replace
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from conftest import attach_exporter
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from google.adk.models.base_llm import BaseLlm
from google.adk.models.llm_request import LlmRequest
from google.adk.models.llm_response import LlmResponse
from google.api_core.exceptions import ServiceUnavailable
from google.genai import types
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter
from opentelemetry.trace import StatusCode
from pydantic import Field
from test_registry import FakeFirestore

from provenance import audit, beliefs, incident, policy, registry, telemetry
from provenance.synthetic import company

_EXPORTER = attach_exporter()

NOW = datetime(2026, 8, 22, 12, 0, 0, tzinfo=UTC)

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


def a_store(*, sre: dict[str, Any] | None = None, **overrides: Any) -> FakeFirestore:
    """The registry, plus the three collections item 10's executor and Policy Engine touch.

    `sre` overrides the *domain* agent's record, which is the one the belief is written under
    (§3.4: memory-domain authority is per agent). `overrides` still go to the Planner, so
    every item-9 call site reads unchanged.
    """
    planner_record = registry.Agent(
        id="remediation-planner",
        version="v3",
        public_key=PLANNER_PEM,
        tool_scope=("ROLLBACK_CONFIG", "DISABLE_COMPLIANCE_CHECKS"),
        memory_domains=(),
        standing="GOOD",
        rejection_window=(),
    )
    sre_record = registry.Agent(
        id="sre-infra-agent",
        version="v1",
        public_key="",
        tool_scope=(),
        memory_domains=("infrastructure",),
        standing="GOOD",
        rejection_window=(),
    )
    service = company.service("inventory-api")
    return FakeFirestore(
        {
            "remediation-planner": registry.to_document(replace(planner_record, **overrides)),
            "sre-infra-agent": registry.to_document(sre_record) | (sre or {}),
        },
        services={
            "inventory-api": {
                **asdict(service),
                # The injected fault, as `scripts/inject_fault.py` writes it.
                "error_rate": 0.38,
                "healthy": False,
            }
        },
        fault_injection={"inventory-api": {"error_rate_spike": True, "rollback_fails": False}},
        beliefs={},
        authorizations={},
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


def a_verification(outcome: str = "CONFIRMED") -> str:
    return json.dumps(
        {
            "outcome": outcome,
            "hypotheses_considered": 2,
            "selected_hypothesis": "predicate_met",
        }
    )


def run(
    replies: list[str],
    *,
    store: FakeFirestore | None = None,
    now: datetime | None = None,
    embed: Any | None = None,
) -> incident.IncidentResult:
    """One incident, with every model call answered from `replies` in order."""
    model = FakeLlm(model="fake-model", replies=list(replies), prompts=[])
    return asyncio.run(
        incident.run_incident(
            a_trigger(),
            now=now,
            embed=embed,
            client=store if store is not None else a_store(),
            planner_key=PLANNER_KEY,
            model_orchestrator=model,
            model_domain=model,
            model_planner=model,
            model_verification=model,
        )
    )


# The four replies a clean incident #1 consumes, in order.
def a_clean_run() -> list[str]:
    return [a_classification(), a_diagnosis(), a_proposal(), a_verification()]


# --- the happy path -----------------------------------------------------------------------


def test_one_trigger_produces_one_rollback_proposal_scoring_2_and_auto_approved(
    spans: InMemorySpanExporter,
) -> None:
    """Item 9's `verify:` line, with the model's cooperation stipulated rather than hoped for."""
    result = run(a_clean_run())

    assert result.outcome == "RESOLVED"
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
    result = run(a_clean_run())
    finished = spans.get_finished_spans()
    root = next(s for s in finished if s.name == telemetry.SPAN_INCIDENT)

    assert root.parent is None
    assert root.attributes is not None
    assert root.attributes["provenance.incident.outcome"] == "RESOLVED"
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
    run(a_clean_run())
    chains = [s for s in spans.get_finished_spans() if s.name == telemetry.SPAN_REASONING_CHAIN]
    assert [s.attributes["provenance.reasoning.step"] for s in chains if s.attributes] == [
        "classification",
        "diagnosis",
        "planning",
        "verification",
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
            a_verification(),
        ]
    )
    assert result.malformed_attempts == 1
    assert result.outcome == "RESOLVED"
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
            a_verification(),
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
            model_verification=model,
        )
    )
    assert "RESTART_EVERYTHING" in model.prompts[-2], "the re-plan prompt carried no reason"


def test_the_planner_is_told_what_healthy_looks_like(spans: InMemorySpanExporter) -> None:
    """Item 11.5: a Planner that does not know nominal writes a predicate nothing can satisfy.

    Found live, not designed. One run in three declared "less than 1%" against a service whose
    healthy error rate is exactly 0.01, and `REFUTED` was the honest answer -- the rollback had
    worked. The number must come off the frozen fixture, never off the trigger: the store this
    test runs against holds the *spiked* 0.38, so sourcing it from what was observed turns the
    last assertion red.

    The ten-run verification then found the sibling defect: a predicate that is satisfiable but
    not *checkable*. One run wrote "the deployed config version will match the last known-good
    version", and the Verification Agent -- shown the deployed version but never told what
    known-good means -- answered `INCONCLUSIVE`, again honestly. Hence the second clause: name
    values literally, not by reference.
    """
    model = FakeLlm(model="fake-model", replies=a_clean_run(), prompts=[])
    asyncio.run(
        incident.run_incident(
            a_trigger(),
            client=a_store(),
            planner_key=PLANNER_KEY,
            model_orchestrator=model,
            model_domain=model,
            model_planner=model,
            model_verification=model,
        )
    )
    planning = model.prompts[2]  # orchestrator, sre_infra, planner
    assert "0.01" in planning and "1%" in planning, (
        "the Planner was not told nominal, in both units"
    )
    assert "strictly above" in planning, "the Planner was not given the floor"
    assert "0.38" not in planning, "the Planner was told the spiked rate, not the nominal one"
    assert 'is v41" and never' in planning, "the Planner was not told to name values literally"


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
    result = run(a_clean_run(), store=a_store(standing="DEGRADED"))
    assert result.outcome == "HELD"
    assert result.decision is not None
    assert result.decision.reason == "STANDING_DEGRADED"
    assert result.decision.score is not None and result.decision.score.score == 2
    # Item 10: a held action executes nothing, so there is nothing to verify and nothing to
    # learn. §2.1 stage 7 parks it on a human; item 30 owns resuming it.
    assert (result.execution, result.verification, result.belief) == (None, None, None)
    names = {s.name for s in spans.get_finished_spans()}
    assert telemetry.SPAN_VERIFICATION_OUTCOME not in names
    assert telemetry.SPAN_BELIEF_COMMIT not in names


# --- item 10: execute, verify, learn -------------------------------------------------------


def test_a_confirmed_verification_writes_one_belief_and_resolves(
    spans: InMemorySpanExporter,
) -> None:
    """Item 10's `verify:` line, end to end: executed, dropped, CONFIRMED, committed."""
    store = a_store()
    result = run(a_clean_run(), store=store)

    assert result.outcome == "RESOLVED"
    assert result.execution is not None
    assert (result.execution.from_version, result.execution.to_version) == ("v42", "v41")
    assert result.verification == "CONFIRMED"
    assert result.belief is not None
    assert (result.belief.outcome, result.belief.reason) == ("COMMIT", "ABOVE_THRESHOLD")
    assert result.belief.confidence == pytest.approx(0.60)

    # The rollback reached the store, and the belief did too. One belief, not two.
    service = store.collections["services"]["inventory-api"]
    assert service["current_config_version"] == "v41"
    assert service["error_rate"] == company.service("inventory-api").error_rate
    assert list(store.collections["beliefs"]) == ["belief-inventory-api"]
    policy.verify_commit(result.belief, policy.public_key_pem())


def test_two_incidents_sharing_a_predicate_store_two_distinct_observations() -> None:
    """The evidence id names the observation, not the sentence the Planner wrote about it.

    Until item 13 the id was `ev-{action.predicate_id()}` — a hash of the success predicate
    — while `beliefs.append()` writes evidence create-if-absent. Two incidents whose Planner
    happened to phrase the predicate identically therefore shared an id while observing at
    different times, so the second write was discarded and the belief ended up citing a
    timestamp nobody had observed, twice. `confidence()` decays from `observed_at`, so the
    stale one is not cosmetic: it ages the fresh observation by however long ago the first ran.
    """
    store = a_store()
    first = run(a_clean_run(), store=store, now=NOW)
    second = run(a_clean_run(), store=store, now=NOW + timedelta(days=1))

    assert first.belief is not None and second.belief is not None
    assert (first.belief.version, second.belief.version) == (1, 2)

    cited = store.collections["beliefs/belief-inventory-api/versions"]["2"]["evidence"]
    assert len(set(cited)) == len(cited) == 2, f"one observation cited twice: {cited}"
    stored = store.collections[beliefs.EVIDENCE_COLLECTION]
    assert sorted(item["observed_at"] for item in stored.values()) == [
        NOW.strftime(beliefs.TIMESTAMP),
        (NOW + timedelta(days=1)).strftime(beliefs.TIMESTAMP),
    ]


def test_the_verification_span_carries_the_predicate_declared_before_execution(
    spans: InMemorySpanExporter,
) -> None:
    """The pairing that makes "pre-declared" checkable rather than asserted (§3.1, item 9).

    The incident span carried this hash before the executor ran; the verification span
    carries it after. Byte-identical, because `predicate_id` hashes the predicate's text
    rather than being assigned per incident -- switch it to a per-incident id and this test
    is the one that says why not.
    """
    run(a_clean_run())
    finished = spans.get_finished_spans()
    root = next(s for s in finished if s.name == telemetry.SPAN_INCIDENT)
    verified = next(s for s in finished if s.name == telemetry.SPAN_VERIFICATION_OUTCOME)

    assert root.attributes is not None and verified.attributes is not None
    assert (
        verified.attributes["provenance.verification.predicate_id"]
        == root.attributes["provenance.incident.predicate_id"]
    )
    assert verified.attributes["provenance.verification.outcome"] == "CONFIRMED"
    assert verified.attributes["provenance.verification.belief_written"] is True
    assert verified.attributes["provenance.action.target"] == "inventory-api"
    # The belief commit nests inside the verification span: `belief_written` is not known
    # until the commit has been attempted.
    belief = next(s for s in finished if s.name == telemetry.SPAN_BELIEF_COMMIT)
    assert belief.parent is not None
    assert verified.context is not None
    assert belief.parent.span_id == verified.context.span_id


def test_an_inconclusive_verification_writes_nothing_and_escalates(
    spans: InMemorySpanExporter,
) -> None:
    """§7.2's third row: "Nothing. No belief, no confidence, no partial credit."

    This is the test a live run cannot honestly produce -- a model asked to be unsure on cue
    is a model told what to answer -- and it is the one guarding the rule that makes the whole
    memory system trustworthy. Commit on INCONCLUSIVE and this goes red.
    """
    store = a_store()
    result = run(
        [a_classification(), a_diagnosis(), a_proposal(), a_verification("INCONCLUSIVE")],
        store=store,
    )

    assert result.outcome == "ESCALATED"
    assert result.verification == "INCONCLUSIVE"
    assert result.belief is None
    assert store.collections["beliefs"] == {}
    # It still executed, and the trace still says so honestly.
    assert result.execution is not None
    verified = next(
        s for s in spans.get_finished_spans() if s.name == telemetry.SPAN_VERIFICATION_OUTCOME
    )
    assert verified.attributes is not None
    assert verified.attributes["provenance.verification.belief_written"] is False
    # Ambiguity is an honest result, so the span is not an error (§8.1).
    assert verified.status.status_code is not StatusCode.ERROR


def test_a_refuted_verification_writes_nothing_yet_either(spans: InMemorySpanExporter) -> None:
    """Item 19 owns the negative belief. Until then REFUTED escalates and learns nothing.

    Stated as a test rather than left implicit so that item 19 *changes* a red assertion
    instead of quietly filling a gap nobody had written down.
    """
    store = a_store()
    result = run(
        [a_classification(), a_diagnosis(), a_proposal(), a_verification("REFUTED")], store=store
    )

    assert result.outcome == "ESCALATED"
    assert result.verification == "REFUTED"
    assert result.belief is None and store.collections["beliefs"] == {}


def test_a_verification_agent_that_cannot_answer_is_inconclusive(
    spans: InMemorySpanExporter,
) -> None:
    """§7.3: "verification agent errors/timeouts -> treated as INCONCLUSIVE".

    The model's queue runs dry on the fourth call, so the agent node fails outright. An
    executed action that reached the end of the loop with no verification span would read as
    an incident nobody checked -- so the control loop emits it, exactly as it owns the
    malformed count (§7.1).
    """
    store = a_store()
    result = run([a_classification(), a_diagnosis(), a_proposal()], store=store)

    assert result.execution is not None, "the rollback should still have executed"
    assert result.verification == "INCONCLUSIVE"
    assert result.outcome == "ESCALATED"
    assert store.collections["beliefs"] == {}
    assert [
        s for s in spans.get_finished_spans() if s.name == telemetry.SPAN_VERIFICATION_OUTCOME
    ], "an executed incident emitted no verification span"


def test_an_execution_failure_escalates_and_verifies_nothing(
    spans: InMemorySpanExporter,
) -> None:
    """§7.3's new row: nothing verified, nothing written, and the outcome recorded not raised."""
    store = a_store()
    del store.collections["fault_injection"]["inventory-api"]
    result = run(a_clean_run(), store=store)

    assert result.outcome == "ESCALATED"
    assert result.execution is None and result.verification is None and result.belief is None
    names = {s.name for s in spans.get_finished_spans()}
    assert telemetry.SPAN_VERIFICATION_OUTCOME not in names
    assert telemetry.SPAN_BELIEF_COMMIT not in names
    root = next(s for s in spans.get_finished_spans() if s.name == telemetry.SPAN_INCIDENT)
    assert root.attributes is not None
    assert root.attributes["provenance.incident.outcome"] == "ESCALATED"


def test_a_planner_that_lost_its_memory_domain_still_executes_but_learns_nothing(
    spans: InMemorySpanExporter,
) -> None:
    """The action path and the memory path are two authorities, and they can disagree.

    The SRE agent holds no `infrastructure` domain here, so §2.2 stage 2 refuses the write --
    but the rollback was authorized on the *action* path and stays executed. The incident
    still resolves; what it does not do is quietly learn from a write it was refused.
    """
    store = a_store(sre={"memory_domains": ["supply-chain"]})
    result = run(a_clean_run(), store=store)

    assert result.verification == "CONFIRMED"
    assert result.belief is not None
    assert (result.belief.outcome, result.belief.reason) == ("REJECT", "DOMAIN_NOT_HELD")
    assert store.collections["beliefs"] == {}
    verified = next(
        s for s in spans.get_finished_spans() if s.name == telemetry.SPAN_VERIFICATION_OUTCOME
    )
    assert verified.attributes is not None
    assert verified.attributes["provenance.verification.belief_written"] is False


# --- the authorization ledger (item 15) --------------------------------------------------------


def ledger(store: FakeFirestore) -> list[dict[str, Any]]:
    return list(store.collections[audit.COLLECTION].values())


def test_an_authorized_action_is_written_to_the_ledger() -> None:
    """§6.4's join, built here because nothing else records what an action rested on.

    `belief_ids` is empty on *this* run because memory is empty when the incident starts —
    incident #1 is the fleet's first encounter with this service. The two tests below are
    the ones that show a recalled belief reaching the record, and a retracted one not.
    """
    store = a_store()
    result = run(a_clean_run(), store=store)

    assert result.outcome == "RESOLVED"
    assert result.decision is not None
    entries = ledger(store)
    assert len(entries) == 1
    entry = entries[0]
    assert entry["action_class"] == "ROLLBACK_CONFIG"
    assert entry["target"] == "inventory-api"
    assert entry["outcome"] == "APPROVE"
    assert entry["signature"] == result.decision.signature
    assert entry["subject"] == result.decision.subject
    assert entry["belief_ids"] == [], "nothing was believed about this service yet"
    assert entry["flagged_by"] == []


def a_prior_belief(store: FakeFirestore, *versions: beliefs.BeliefVersion) -> None:
    """Whatever the fleet already believed about `inventory-api` when the incident woke."""
    for version in versions:
        asyncio.run(
            beliefs.append(
                version,
                (
                    beliefs.Evidence(
                        id=f"ev-prior-{version.version}",
                        source_id="firestore:services/inventory-api",
                        source_class="verified_system_observation",
                        observed_at=f"2026-08-0{version.version}T12:00:00Z",
                        ingested_at=f"2026-08-0{version.version}T12:00:00Z",
                        payload_hash="a" * 64,
                        verifiable_by="re-read services/inventory-api",
                    ),
                ),
                client=store,
            )
        )


def a_prior_version(version: int, **overrides: Any) -> beliefs.BeliefVersion:
    fields: dict[str, Any] = {
        "belief_id": "belief-inventory-api",
        "version": version,
        "scope": "ENTITY",
        "domain": "infrastructure",
        "entity": "inventory-api",
        "status": incident.BELIEF_STATUS,
        "confidence": 0.60,
        "threshold": 0.50,
        "evidence_ids": (f"ev-prior-{version}",),
        "authority": "sre-infra-agent@v1 (standing: GOOD)",
        "committed_at": f"2026-08-0{version}T12:00:00Z",
        "committed_by": "memory-policy-engine",
        "signature": "ecdsa:beef",
        "supersedes": None if version == 1 else version - 1,
        "half_life_days": 30.0,
        "expires_at": "2026-09-21T12:00:00Z",
        "on_expiry": "REVERIFY",
    }
    return beliefs.BeliefVersion(**(fields | overrides))


def test_a_recalled_entity_belief_is_what_the_action_is_recorded_as_resting_on() -> None:
    # Item 16. The exact-key read (§6.1) reaches the ledger, which is what makes §6.4's
    # "flag every action authorized on that belief" find anything at all on a real incident.
    store = a_store()
    a_prior_belief(store, a_prior_version(1))

    result = run(a_clean_run(), store=store)

    assert result.outcome == "RESOLVED"
    assert ledger(store)[0]["belief_ids"] == ["belief-inventory-api"]


def test_the_ledger_cites_the_entity_belief_and_never_the_advisory_class_one() -> None:
    # §6.2 caps a class belief as ADVISORY ONLY: it may reorder what gets investigated and may
    # never be the evidence that authorizes an action. `belief_ids` is the record of what an
    # action rested on, so a class belief in it would make §6.4's retraction flag actions on
    # grounds §6.2 says they could not have had. Both beliefs reach the prompt; one is cited.
    store = a_store()
    a_prior_belief(store, a_prior_version(1))
    a_prior_belief(
        store,
        a_prior_version(
            1,
            belief_id="belief-class-config-deploy",
            scope="CLASS",
            entity="service.config_deploy",
            statement="config deploys correlate with error-rate spikes on tier-2 services",
        ),
    )

    async def embed(texts: Any) -> tuple[tuple[float, ...], ...]:
        return tuple((1.0, 0.0) for _ in texts)  # everything is a perfect match

    result = run(a_clean_run(), store=store, embed=embed)

    assert result.outcome == "RESOLVED"
    entry = ledger(store)[0]
    assert entry["belief_ids"] == ["belief-inventory-api"]
    assert "belief-class-config-deploy" not in entry["belief_ids"]


def test_a_retracted_belief_is_recalled_by_nothing_and_cited_by_nothing(
    spans: InMemorySpanExporter,
) -> None:
    # ROADMAP item 16's verify line, at the incident boundary rather than the unit one: a
    # belief the exact-key read would have found is RETRACTED, so it reaches neither the
    # prompt, nor the reasoning spans, nor the record of what the action rested on.
    store = a_store()
    a_prior_belief(store, a_prior_version(1), a_prior_version(2, status="RETRACTED"))

    result = run(a_clean_run(), store=store)

    assert result.outcome == "RESOLVED"
    assert ledger(store)[0]["belief_ids"] == []
    chains = [s for s in spans.get_finished_spans() if s.name == telemetry.SPAN_REASONING_CHAIN]
    assert chains
    for span in chains:
        assert span.attributes is not None
        assert span.attributes["provenance.recall.belief_ids"] == ()


def test_a_held_action_is_not_recorded_as_authorized() -> None:
    """§6.4 flags what was *authorized*. A hold parks on a human; nothing was authorized."""
    store = a_store(standing="DEGRADED")

    result = run(a_clean_run()[:3], store=store)

    assert result.outcome == "HELD"
    assert ledger(store) == []


def test_a_denied_action_is_not_recorded_either() -> None:
    store = a_store(standing="SUSPENDED")

    result = run(a_clean_run()[:3], store=store)

    assert result.outcome == "DENIED"
    assert ledger(store) == []


def test_an_unwritable_ledger_escalates_rather_than_executing() -> None:
    """§7.3 fail-closed: an authorization nothing recorded is one no retraction can flag.

    The alternative is an action that executed while §6.4's promise quietly stopped applying
    to it, which is the failure this item exists to remove rather than to relocate.
    """

    class _LedgerFails(FakeFirestore):
        def collection(self, name: str) -> Any:
            if name == audit.COLLECTION:
                raise ServiceUnavailable("firestore is down")
            return super().collection(name)

    store = a_store()
    broken = _LedgerFails(store.docs)
    broken.collections = store.collections

    result = run(a_clean_run(), store=broken)

    assert result.outcome == "ESCALATED"
    assert result.execution is None, "nothing may execute on an unrecorded authorization"
    assert result.verification is None
    assert store.collections["services"]["inventory-api"]["error_rate"] == 0.38, "no rollback"


# --- incident #2: the fleet remembers (item 18) -------------------------------------------


def test_recall_reaches_the_first_span_before_the_domain_agent_has_a_hypothesis(
    spans: InMemorySpanExporter,
) -> None:
    """Item 18's `verify:` line, offline: the only assertion in this suite about span *order*.

    There is no dedicated recall span and deliberately no sixth shape. `recall()` resolves in
    `run_incident()` before `build_graph()`, so what the trace can show is stronger than the
    line asks for: the very first reasoning span the graph opens already carries the recalled
    belief, and it opened before the domain agent's span did. Reverse the comparison and this
    goes red; move the recall call after `build_graph()` and the attribute goes empty.
    """
    store = a_store()
    a_prior_belief(store, a_prior_version(1))

    result = run(a_clean_run(), store=store)

    assert result.outcome == "RESOLVED"
    by_step = {
        span.attributes["provenance.reasoning.step"]: span
        for span in spans.get_finished_spans()
        if span.name == telemetry.SPAN_REASONING_CHAIN and span.attributes is not None
    }
    classification, diagnosis = by_step["classification"], by_step["diagnosis"]
    assert classification.attributes is not None and diagnosis.attributes is not None
    assert classification.attributes["provenance.recall.belief_ids"] == ("belief-inventory-api",)
    assert classification.start_time < diagnosis.start_time


def test_a_second_incident_supersedes_the_belief_the_first_one_wrote() -> None:
    """The same deviation twice, with memory left standing in between.

    The confidence does not move, and that is §4.3 rather than a disappointment: both runs
    contribute `verified_system_observation`, and the formula collapses a source class to its
    least-decayed item. What changes is the version and what the ledger cites — memory
    accumulated evidence, not certainty.

    The two `now` values are a minute apart on purpose. §2.2's novelty check compares
    `(source_id, observed_at)` pairs and `beliefs.TIMESTAMP` has second resolution, so two
    runs inside one second would be refused `NO_NEW_EVIDENCE` — correctly.
    """
    store = a_store()

    first = run(a_clean_run(), store=store, now=NOW)
    second = run(a_clean_run(), store=store, now=NOW + timedelta(minutes=1))

    assert (first.outcome, second.outcome) == ("RESOLVED", "RESOLVED")
    assert first.belief is not None and second.belief is not None
    assert (first.belief.version, second.belief.version) == (1, 2)
    assert second.belief.outcome == "COMMIT"
    assert second.belief.confidence == first.belief.confidence == 0.60

    current = asyncio.run(beliefs.current("belief-inventory-api", client=store))
    assert current.supersedes == 1
    assert len(current.evidence_ids) == 2, "a superseding version cites the accumulated set"

    cold, remembered = ledger(store)
    assert cold["belief_ids"] == [], "the first incident had nothing to recall"
    assert remembered["belief_ids"] == ["belief-inventory-api"]
