#!/usr/bin/env python3
"""Emit one span of each shape to Cloud Trace and read the trace back. ROADMAP item 2's
`verify:` line — "a hand-emitted span for each shape renders in Cloud Trace with trace IDs
intact" — checked by the API rather than by eye.

    GOOGLE_CLOUD_PROJECT=provenance-hackathon .venv/bin/python scripts/emit_trace_samples.py

Exits non-zero if any shape is missing from the trace. Not run in CI: CI has no
credentials, and the offline half of the contract is `tests/test_telemetry_schema.py`.
"""

from __future__ import annotations

import os
import sys
import time

from google.api_core.exceptions import NotFound
from google.cloud import trace_v1
from opentelemetry import trace

from provenance import telemetry

# Cloud Trace indexing lagged ~2 minutes when this was first run against
# provenance-hackathon, so the budget is generous rather than tight.
POLL_ATTEMPTS = 48
POLL_INTERVAL_S = 5.0


def emit_all() -> str:
    """Emit the four shapes under one parent and return the hex trace ID they share."""
    tracer = trace.get_tracer("provenance.samples")
    with tracer.start_as_current_span("provenance.samples") as root:
        # ROLLBACK_CONFIG — the ARCHITECTURE §4.2 worked example, risk 2, auto-approved.
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
        ) as auth:
            auth.set_risk(base=1, criticality=1, blast=0, irreversibility=0, score=2)
            auth.set_outcome(
                outcome="APPROVE", stage="risk", reason="RISK_THRESHOLD", signature="ecdsa:sample"
            )

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
            evidence_ids=["ev-118", "ev-140", "ev-141"],
            source_classes=["verified_system_observation", "third_party_audit"],
            novel_count=2,
            supersedes="belief-17",
        ) as belief:
            belief.set_outcome(outcome="COMMIT", reason="ABOVE_THRESHOLD", signature="ecdsa:sample")

        with telemetry.verification_outcome(
            predicate_id="pred-error-rate-below-baseline",
            model="gemini-3.5-flash",
            action_class="ROLLBACK_CONFIG",
            target="inventory-api",
            attempt=1,
        ) as verification:
            verification.set_outcome(outcome="CONFIRMED", belief_written=True)

        with telemetry.reasoning_chain(
            agent_id="sre-agent",
            agent_version="v1",
            model="gemini-2.5-pro",
            step="diagnosis",
            recall_belief_ids=["belief-42"],
        ) as reasoning:
            reasoning.set_result(
                hypotheses_considered=3,
                selected_hypothesis="config_regression",
                input_tokens=1840,
                output_tokens=220,
                model_calls=1,
            )

        assert root.get_span_context() is not None
        return format(root.get_span_context().trace_id, "032x")


def read_back(project_id: str, trace_id: str, expected: set[str]) -> set[str]:
    """Poll until Cloud Trace holds every expected shape; return the span names it has."""
    client = trace_v1.TraceServiceClient()
    names: set[str] = set()
    for attempt in range(1, POLL_ATTEMPTS + 1):
        try:
            names = {
                span.name
                for span in client.get_trace(project_id=project_id, trace_id=trace_id).spans
            }
        except NotFound:
            names = set()
        if expected <= names:
            return names
        waited = int(attempt * POLL_INTERVAL_S)
        print(f"    {len(names)}/{len(expected)} shape(s) after {waited}s…", flush=True)
        time.sleep(POLL_INTERVAL_S)
    return names


def main() -> int:
    project_id = os.environ.get("GOOGLE_CLOUD_PROJECT")
    if not telemetry.configure_tracing(project_id):
        print("GOOGLE_CLOUD_PROJECT is not set; nothing would be exported.", file=sys.stderr)
        return 1
    assert project_id is not None

    trace_id = emit_all()
    provider = trace.get_tracer_provider()
    provider.force_flush()  # type: ignore[attr-defined]
    print(f"--> emitted trace {trace_id}")

    expected = {
        telemetry.SPAN_AUTHORIZATION_DECISION,
        telemetry.SPAN_BELIEF_COMMIT,
        telemetry.SPAN_VERIFICATION_OUTCOME,
        telemetry.SPAN_REASONING_CHAIN,
    }
    print("--> reading it back from Cloud Trace (indexing usually takes a minute or two)")
    names = read_back(project_id, trace_id, expected)
    url = f"https://console.cloud.google.com/traces/list?project={project_id}&tid={trace_id}"

    missing = expected - names
    if missing:
        print(f"MISSING from the trace: {sorted(missing)}", file=sys.stderr)
        print(url, file=sys.stderr)
        return 1
    for name in sorted(expected):
        print(f"    ok  {name}")
    print(f"--> all four shapes on trace {trace_id}\n    {url}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
