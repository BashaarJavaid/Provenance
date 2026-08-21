#!/usr/bin/env python3
"""Check ROADMAP item 7's `verify:` line against real GCP: the two worked examples, live.

    PROVENANCE_PLANNER_KEY="$(cat planner.pem)" \
    GOOGLE_CLOUD_PROJECT=provenance-hackathon .venv/bin/python scripts/verify_gateway.py

Four claims, checked mechanically rather than by eye — the same posture as item 2's trace
read-back, item 3's `/health` curl, item 4's document read-back and item 5's standing flip:

  1. `ROLLBACK_CONFIG(inventory-api)` scores exactly **2** and is auto-approved.
  2. `DISABLE_COMPLIANCE_CHECKS(SUP-042)` scores exactly **11** and is held for a human.
  3. An unregistered identity is denied — proving the registry read is live Firestore and
     not a fixture, and that §7.3's fail-closed posture holds against the real thing.
  4. Both decisions verify against `gateway.public_key_pem()`, and both spans reach Cloud
     Trace carrying the §4.2 arithmetic, with the components summing to the score.

Nothing here mutates any stored state: it reads the registry and emits spans, and that is
all. Not run in CI — CI has no credentials. The offline half is `tests/test_gateway.py`,
`tests/test_risk.py` and `tests/test_credentials.py`.

**The private key.** `scripts/seed_registry.py` prints each agent's private half exactly
once and never stores it (ADR-010), so this script cannot recover it and will not invent a
key store to hold it. Export the PEM as `PROVENANCE_PLANNER_KEY`; if you no longer have it,
`scripts/seed_registry.py --rotate remediation-planner` mints a new one and prints it.
"""

from __future__ import annotations

import asyncio
import os
import sys
import time
from datetime import UTC, datetime
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from google.api_core.exceptions import NotFound
from google.cloud import firestore, trace_v1
from opentelemetry import trace

from provenance import credentials, gateway, registry, telemetry

AGENT_ID = "remediation-planner"
POLL_ATTEMPTS = 24
POLL_INTERVAL_S = 10.0

ROLLBACK = {
    "action_class": "ROLLBACK_CONFIG",
    "target": "inventory-api",
    "target_tier": "tier2",
    "blast_radius": "single-service",
    "reversible": True,
    "evidence_refs": ["ev-118"],
    "success_predicate": "error_rate < 0.05 within 10m",
    "proposed_by": f"{AGENT_ID}@v1",
}

DISABLE = {
    "action_class": "DISABLE_COMPLIANCE_CHECKS",
    "target": "SUP-042",
    "target_tier": "tier1",
    "blast_radius": "org-wide",
    "reversible": False,
    "evidence_refs": ["ev-140"],
    "success_predicate": "compliance_checks_enabled == false",
    "proposed_by": f"{AGENT_ID}@v1",
}


def load_private_key(pem: str) -> ec.EllipticCurvePrivateKey:
    key = serialization.load_pem_private_key(pem.encode(), password=None)
    if not isinstance(key, ec.EllipticCurvePrivateKey):
        raise TypeError("PROVENANCE_PLANNER_KEY is not an EC private key")
    return key


def report(label: str, decision: gateway.Decision) -> None:
    total = "—" if decision.score is None else str(decision.score.score)
    print(f"    {label:<44} {decision.outcome:<14} stage={decision.stage:<9} risk={total}")


async def run(project_id: str, private_key: ec.EllipticCurvePrivateKey) -> tuple[int, str]:
    """Authorize three proposals against the live registry. Returns (failures, trace id)."""
    client = firestore.AsyncClient(project=project_id)
    now = datetime.now(UTC)
    failures = 0

    tracer = trace.get_tracer("provenance.verify_gateway")
    with tracer.start_as_current_span("provenance.verify_gateway") as root:
        trace_id = format(root.get_span_context().trace_id, "032x")

        # The agent's version has to match the record, or stage 2 denies before anything
        # interesting happens. Read it rather than assuming v1: --rotate bumps it.
        agent = await registry.get_agent(AGENT_ID, client=client)
        print(
            f"==> {registry.COLLECTION}/{AGENT_ID} version={agent.version} standing={agent.standing}"
        )
        credential = credentials.mint(AGENT_ID, agent.version, private_key, now=now)

        rollback = await gateway.authorize(
            dict(ROLLBACK) | {"proposed_by": f"{AGENT_ID}@{agent.version}"},
            credential,
            now=now,
            client=client,
        )
        report("ROLLBACK_CONFIG(inventory-api)", rollback)
        if rollback.outcome != "APPROVE" or rollback.score is None or rollback.score.score != 2:
            print("FAIL: §4.2's first worked example must be APPROVE at exactly 2", file=sys.stderr)
            failures += 1

        disable = await gateway.authorize(
            dict(DISABLE) | {"proposed_by": f"{AGENT_ID}@{agent.version}"},
            credential,
            now=now,
            client=client,
        )
        report("DISABLE_COMPLIANCE_CHECKS(SUP-042)", disable)
        if disable.outcome != "HOLD" or disable.score is None or disable.score.score != 11:
            print("FAIL: §4.2's second worked example must be HOLD at exactly 11", file=sys.stderr)
            failures += 1

        # The registry read is live Firestore, not a fixture: an id that is not in it denies.
        ghost = credentials.mint("ghost-agent", "v1", private_key, now=now)
        unregistered = await gateway.authorize(
            dict(ROLLBACK) | {"proposed_by": "ghost-agent@v1"}, ghost, now=now, client=client
        )
        report("ROLLBACK_CONFIG from an unregistered id", unregistered)
        if (unregistered.outcome, unregistered.reason) != ("DENY", "AGENT_NOT_REGISTERED"):
            print("FAIL: an unregistered identity must be denied (§7.3)", file=sys.stderr)
            failures += 1

        # Every outcome, denials included, is signed (§2.1 stage 6).
        pem = gateway.public_key_pem()
        for label, decision in (
            ("rollback", rollback),
            ("disable", disable),
            ("unregistered", unregistered),
        ):
            try:
                gateway.verify_decision(decision, pem)
            except gateway.DecisionInvalid as exc:
                print(f"FAIL: {label}'s signature does not verify ({exc})", file=sys.stderr)
                failures += 1

    return failures, trace_id


def read_back(project_id: str, trace_id: str) -> list[Any]:
    """Poll until Cloud Trace holds the authorization spans; return them."""
    client = trace_v1.TraceServiceClient()
    for attempt in range(1, POLL_ATTEMPTS + 1):
        try:
            spans = [
                span
                for span in client.get_trace(project_id=project_id, trace_id=trace_id).spans
                if span.name == telemetry.SPAN_AUTHORIZATION_DECISION
            ]
        except NotFound:
            spans = []
        if len(spans) >= 3:
            return spans
        print(
            f"    {len(spans)}/3 decision span(s) after {int(attempt * POLL_INTERVAL_S)}s…",
            flush=True,
        )
        time.sleep(POLL_INTERVAL_S)
    return []


def label(labels: dict[str, str], attr: str) -> int | None:
    """One risk component off a Cloud Trace span.

    The v1 API surfaces OTel attributes as string `labels`, and prefixes some keys with a
    slash depending on how they were ingested — both spellings are tried rather than
    guessed at, since a wrong guess here would silently skip the arithmetic check.
    """
    raw = labels.get(f"/{attr}") or labels.get(attr)
    return None if raw is None else int(raw)


def check_spans(spans: list[Any]) -> int:
    """The risk breakdown must travel with the decision, and must add up (§8.1)."""
    failures = 0
    scored = 0
    for span in spans:
        labels = dict(span.labels)
        outcome = labels.get(f"/{telemetry.ATTR_DECISION_OUTCOME}") or labels.get(
            telemetry.ATTR_DECISION_OUTCOME
        )
        if outcome is None:
            print(f"FAIL: a decision span carries no outcome ({sorted(labels)})", file=sys.stderr)
            failures += 1
            continue

        total = label(labels, telemetry.ATTR_RISK_SCORE)
        if total is None:
            continue  # a denial before the risk table correctly carries no score
        scored += 1
        parts = [
            label(labels, telemetry.ATTR_RISK_BASE),
            label(labels, telemetry.ATTR_RISK_CRITICALITY),
            label(labels, telemetry.ATTR_RISK_BLAST),
            label(labels, telemetry.ATTR_RISK_IRREVERSIBILITY),
        ]
        if None in parts or sum(p for p in parts if p is not None) != total:
            print(f"FAIL: risk {parts} does not sum to {total}", file=sys.stderr)
            failures += 1
        else:
            print(f"    ok  {outcome:<14} risk {' + '.join(str(p) for p in parts)} = {total}")

    if scored != 2:
        print(f"FAIL: expected 2 scored decisions in the trace, found {scored}", file=sys.stderr)
        failures += 1
    return failures


def main() -> int:
    project_id = os.environ.get("GOOGLE_CLOUD_PROJECT")
    pem = os.environ.get("PROVENANCE_PLANNER_KEY")
    if not project_id:
        print("GOOGLE_CLOUD_PROJECT is not set.", file=sys.stderr)
        return 1
    if not pem:
        print(
            "PROVENANCE_PLANNER_KEY is not set. seed_registry.py prints each private key\n"
            "once and stores it nowhere (ADR-010); if you no longer have it, run\n"
            "    scripts/seed_registry.py --rotate remediation-planner",
            file=sys.stderr,
        )
        return 1
    if not telemetry.configure_tracing(project_id):
        print("tracing did not configure; the spans would not be exported.", file=sys.stderr)
        return 1

    failures, trace_id = asyncio.run(run(project_id, load_private_key(pem)))
    provider = trace.get_tracer_provider()
    provider.force_flush()  # type: ignore[attr-defined]

    print(f"--> reading trace {trace_id} back from Cloud Trace (indexing takes a minute or two)")
    spans = read_back(project_id, trace_id)
    url = f"https://console.cloud.google.com/traces/list?project={project_id}&tid={trace_id}"
    if len(spans) < 3:
        print(f"FAIL: only {len(spans)} of 3 decision spans reached Cloud Trace", file=sys.stderr)
        print(url, file=sys.stderr)
        return 1
    failures += check_spans(spans)

    if failures:
        print(f"\n{failures} check(s) failed.\n{url}", file=sys.stderr)
        return 1
    print("\n--> the gateway scores 2 and 11, denies the unregistered id, and signs all three")
    print(f"    {url}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
