#!/usr/bin/env python3
"""Check ROADMAP item 8's `verify:` line against real GCP: a denial caused by a registry entry.

    PROVENANCE_PLANNER_KEY="$(cat planner.pem)" \
    GOOGLE_CLOUD_PROJECT=provenance-hackathon \
    .venv/bin/python scripts/verify_denial_by_registry.py

The demo's registry beat. One proposal -- §4.2's first worked example, `ROLLBACK_CONFIG(
inventory-api)`, which scores exactly 2 -- authorized three times against live Firestore while
only one thing changes between the runs: the agent's stored `standing`.

  1. `GOOD` standing    -> APPROVE at 2.
  2. `SUSPENDED`        -> DENY, stage=registry, reason=STANDING_SUSPENDED, **no score at all**.
  3. `DEGRADED`         -> HOLD, stage=registry, reason=STANDING_DEGRADED, **scored 2 anyway** --
     §3.4's "regardless of risk score", which only means something if the score is there.

Then both denials are read back out of Cloud Trace, because "appear in the signed ledger citing
the registry entry as cause" is the claim, and the ledger is the signed
`provenance.authorization.decision` stream (item 7); rendering it on screen is item 11's job.
Each span must carry `decision.stage=registry`, the standing that caused it, and a signature.

**This script mutates stored state, unlike `scripts/verify_gateway.py`.** The flips run inside a
`try/finally` that restores the original standing on any exit path -- a deliberate departure from
`scripts/verify_registry.py`'s unconditional restore line. `scripts/seed_registry.py` has no
`--reset` and can never forgive a stranded `SUSPENDED` (ADR-010), so a crash between the flip and
the restore would leave the fleet's only tool-scoped agent permanently denied, repairable by hand
alone. Not run in CI -- CI has no credentials. The offline half is `tests/test_gateway.py`.

**The private key.** `scripts/seed_registry.py` prints each agent's private half exactly once and
never stores it (ADR-010). Export the PEM as `PROVENANCE_PLANNER_KEY`; if you no longer have it,
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
from provenance.telemetry import Standing

AGENT_ID = "remediation-planner"
POLL_ATTEMPTS = 24
POLL_INTERVAL_S = 10.0

# §4.2's first worked example: base 1 + tier2 1 + single-service 0 + reversible 0 = 2.
# The same dict is authorized under all three standings; nothing about the action ever moves.
ROLLBACK = {
    "action_class": "ROLLBACK_CONFIG",
    "target": "inventory-api",
    "target_tier": "tier2",
    "blast_radius": "single-service",
    "reversible": True,
    "evidence_refs": ["ev-118"],
    "success_predicate": "error_rate < 0.05 within 10m",
}

# What each run must produce, and what its span must say. `standing` is both the flip we write
# and the attribute the span has to carry back -- that is "citing the registry entry as cause".
EXPECTED = {
    "GOOD": ("APPROVE", "risk", "RISK_THRESHOLD", 2),
    "SUSPENDED": ("DENY", "registry", "STANDING_SUSPENDED", None),
    "DEGRADED": ("HOLD", "registry", "STANDING_DEGRADED", 2),
}


def load_private_key(pem: str) -> ec.EllipticCurvePrivateKey:
    key = serialization.load_pem_private_key(pem.encode(), password=None)
    if not isinstance(key, ec.EllipticCurvePrivateKey):
        raise TypeError("PROVENANCE_PLANNER_KEY is not an EC private key")
    return key


def report(standing: str, decision: gateway.Decision) -> None:
    total = "—" if decision.score is None else str(decision.score.score)
    print(
        f"    standing={standing:<10} {decision.outcome:<8} stage={decision.stage:<9} "
        f"reason={decision.reason:<19} risk={total}"
    )


def check(standing: str, decision: gateway.Decision) -> int:
    """One run against its row in EXPECTED. Returns the number of failed checks."""
    outcome, stage, reason, score = EXPECTED[standing]
    failures = 0
    if (decision.outcome, decision.stage, decision.reason) != (outcome, stage, reason):
        print(
            f"FAIL: {standing} must be {outcome}/{stage}/{reason}, got "
            f"{decision.outcome}/{decision.stage}/{decision.reason}",
            file=sys.stderr,
        )
        failures += 1
    if score is None and decision.score is not None:
        # ADR-012: a denial owes the human no arithmetic, so there is none to carry.
        print(f"FAIL: a {standing} denial must carry no score", file=sys.stderr)
        failures += 1
    if score is not None and (decision.score is None or decision.score.score != score):
        got = "none" if decision.score is None else str(decision.score.score)
        print(f"FAIL: {standing} must score exactly {score}, got {got}", file=sys.stderr)
        failures += 1
    return failures


async def run(project_id: str, private_key: ec.EllipticCurvePrivateKey) -> tuple[int, str]:
    """Authorize one proposal under three standings. Returns (failures, trace id)."""
    client = firestore.AsyncClient(project=project_id)
    now = datetime.now(UTC)
    failures = 0

    tracer = trace.get_tracer("provenance.verify_denial_by_registry")
    with tracer.start_as_current_span("provenance.verify_denial_by_registry") as root:
        trace_id = format(root.get_span_context().trace_id, "032x")

        # Read the version rather than assuming v2: --rotate bumps it, and a credential minted
        # for a superseded version is denied at stage 2 before standing is ever consulted.
        agent = await registry.get_agent(AGENT_ID, client=client)
        print(
            f"==> {registry.COLLECTION}/{AGENT_ID} version={agent.version} standing={agent.standing}"
        )
        if agent.standing != "GOOD":
            print(
                f"FAIL: {AGENT_ID} is stored as {agent.standing}, not GOOD. The control run would\n"
                "      prove nothing and the restore would cement it. Reinstate it deliberately:\n"
                f'        registry.set_standing("{AGENT_ID}", "GOOD")',
                file=sys.stderr,
            )
            return 1, trace_id

        credential = credentials.mint(AGENT_ID, agent.version, private_key, now=now)
        proposal = dict(ROLLBACK) | {"proposed_by": f"{AGENT_ID}@{agent.version}"}
        decisions: dict[str, gateway.Decision] = {}

        # The control: at GOOD this proposal auto-approves, so what the next two runs change is
        # the registry entry and nothing else.
        decisions["GOOD"] = await gateway.authorize(proposal, credential, now=now, client=client)
        report("GOOD", decisions["GOOD"])
        failures += check("GOOD", decisions["GOOD"])

        flips: tuple[Standing, ...] = ("SUSPENDED", "DEGRADED")
        try:
            for standing in flips:
                print(f"--> set_standing({standing})")
                await registry.set_standing(AGENT_ID, standing, client=client)
                decisions[standing] = await gateway.authorize(
                    proposal, credential, now=now, client=client
                )
                report(standing, decisions[standing])
                failures += check(standing, decisions[standing])
        finally:
            # Any exit path, including an exception or a Ctrl-C between the two flips.
            print(f"--> restoring to {agent.standing}")
            await registry.set_standing(AGENT_ID, agent.standing, client=client)
            restored = await registry.get_agent(AGENT_ID, client=client)
            if restored.standing != agent.standing:
                print(
                    f"FAIL: restore left standing at {restored.standing!r}, "
                    f"not {agent.standing!r}.",
                    file=sys.stderr,
                )
                failures += 1

        # Every outcome, denials included, is signed (§2.1 stage 6).
        pem = gateway.public_key_pem()
        for label, decision in decisions.items():
            try:
                gateway.verify_decision(decision, pem)
            except gateway.DecisionInvalid as exc:
                print(f"FAIL: the {label} decision's signature does not verify ({exc})")
                failures += 1

    return failures, trace_id


def read_back(project_id: str, trace_id: str) -> list[Any]:
    """Poll until Cloud Trace holds the three authorization spans; return them."""
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


def attribute(labels: dict[str, str], attr: str) -> str | None:
    """One attribute off a Cloud Trace span.

    The v1 API surfaces OTel attributes as string `labels`, and prefixes some keys with a
    slash depending on how they were ingested -- both spellings are tried rather than guessed
    at, since a wrong guess here would silently skip the check it is feeding.
    """
    return labels.get(f"/{attr}") or labels.get(attr)


def check_spans(spans: list[Any]) -> int:
    """Both denials must reach the ledger citing the registry entry that caused them (§8.1)."""
    failures = 0
    seen: dict[str, dict[str, str]] = {}
    for span in spans:
        labels = dict(span.labels)
        reason = attribute(labels, telemetry.ATTR_DECISION_REASON)
        if reason is None:
            print(f"FAIL: a decision span carries no reason ({sorted(labels)})", file=sys.stderr)
            failures += 1
            continue
        seen[reason] = labels

    for standing, (outcome, stage, reason, score) in EXPECTED.items():
        labels = seen.get(reason, {})
        if not labels:
            print(f"FAIL: no {reason} span reached Cloud Trace", file=sys.stderr)
            failures += 1
            continue

        # The cause, as the ledger records it: the stage, and the standing that decided it.
        got = (
            attribute(labels, telemetry.ATTR_DECISION_OUTCOME),
            attribute(labels, telemetry.ATTR_DECISION_STAGE),
            attribute(labels, telemetry.ATTR_AGENT_STANDING),
        )
        if got != (outcome, stage, standing):
            print(f"FAIL: {reason} span says {got}, expected {(outcome, stage, standing)}")
            failures += 1
        if not attribute(labels, telemetry.ATTR_DECISION_SIGNATURE):
            print(f"FAIL: the {reason} span carries no signature", file=sys.stderr)
            failures += 1

        total = attribute(labels, telemetry.ATTR_RISK_SCORE)
        if score is None:
            # Absent means omitted, never emitted empty -- the denial carries no arithmetic.
            if total is not None:
                print(f"FAIL: the {reason} span carries a risk score ({total})", file=sys.stderr)
                failures += 1
            print(f"    ok  {reason:<19} {outcome:<8} stage={stage:<9} no risk block")
            continue

        parts = [
            attribute(labels, attr)
            for attr in (
                telemetry.ATTR_RISK_BASE,
                telemetry.ATTR_RISK_CRITICALITY,
                telemetry.ATTR_RISK_BLAST,
                telemetry.ATTR_RISK_IRREVERSIBILITY,
            )
        ]
        if total is None or None in parts:
            print(f"FAIL: the {reason} span's risk block is incomplete", file=sys.stderr)
            failures += 1
            continue
        numbers = [int(p) for p in parts if p is not None]
        if sum(numbers) != int(total) or int(total) != score:
            print(f"FAIL: {reason} risk {numbers} does not sum to {score}", file=sys.stderr)
            failures += 1
        else:
            summed = " + ".join(str(n) for n in numbers)
            print(f"    ok  {reason:<19} {outcome:<8} stage={stage:<9} risk {summed} = {total}")
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

    try:
        failures, trace_id = asyncio.run(run(project_id, load_private_key(pem)))
    except registry.AgentNotRegistered:
        print(f"FAIL: {AGENT_ID} is not registered. Seed it first:", file=sys.stderr)
        print(
            f"        GOOGLE_CLOUD_PROJECT={project_id} .venv/bin/python scripts/seed_registry.py",
            file=sys.stderr,
        )
        return 1
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
    print("\n--> one proposal, three standings: approved, denied, and held — by the registry alone")
    print(f"    {url}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
