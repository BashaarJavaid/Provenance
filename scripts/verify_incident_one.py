#!/usr/bin/env python3
"""Check ROADMAP item 9's `verify:` line against real GCP and a real model.

    PROVENANCE_PLANNER_KEY="$(cat ~/planner.pem)" \
    GOOGLE_CLOUD_PROJECT=provenance-hackathon \
    GOOGLE_GENAI_USE_VERTEXAI=1 GOOGLE_CLOUD_LOCATION=global \
    .venv/bin/python scripts/verify_incident_one.py

The line: "the injected `inventory-api` error-rate spike produces exactly one typed
`ROLLBACK_CONFIG` proposal, risk 2, auto-approved." Three real Gemini calls sit between the
trigger and the score, so the point of this script is that the *deterministic* half holds
whatever the models say: the tool registry and entity model overrule the Planner's declared
fields, and the risk table -- not the reasoning -- produces the 2.

"Exactly one" is counted, not assumed: one `provenance.authorization.decision` span on the
trace, and zero malformed re-plans. Two proposals would mean §7.1's budget was spent.

**This script mutates stored state.** The fault injection runs inside a `try/finally` that
clears it on any exit path, including Ctrl-C -- item 8's lesson, for the same reason: a crash
between the injection and the restore leaves the demo's service permanently spiked, and
`seed_firestore.py` skips existing documents so a re-seed will not put it back. It refuses to
run if the switch is already on, because then the restore would cement someone else's state.

Set `PROVENANCE_SERVICE_URL` and `PROVENANCE_TRIGGER_TOKEN` to also check the deployed
`POST /trigger` route -- 403 unauthenticated, 200 with the token. Skipped, loudly, without them.

Not run in CI: CI has no credentials and must not spend model tokens. The offline half is
`tests/test_incident.py`, which is where the malformed-retry and unroutable paths are proved,
since a real model cannot be asked to misbehave on cue.
"""

from __future__ import annotations

import asyncio
import os
import sys
import time
from typing import Any

import httpx
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from google.api_core.exceptions import NotFound
from google.cloud import firestore, trace_v1
from opentelemetry import trace

from provenance import action, gateway, incident, telemetry
from provenance.synthetic import company

TARGET = "inventory-api"
SPIKED_ERROR_RATE = 0.38
OBSERVED_AT = "2026-08-21T14:06:00Z"
POLL_ATTEMPTS = 24
POLL_INTERVAL_S = 10.0

# §4.2's first worked example, which the fleet has to arrive at on its own:
# base 1 + tier2 1 + single-service 0 + reversible 0 = 2.
EXPECTED_SCORE = 2
EXPECTED_COMPONENTS = (1, 1, 0, 0)


def load_private_key(pem: str) -> ec.EllipticCurvePrivateKey:
    key = serialization.load_pem_private_key(pem.encode(), password=None)
    if not isinstance(key, ec.EllipticCurvePrivateKey):
        raise TypeError("PROVENANCE_PLANNER_KEY is not an EC private key")
    return key


def set_fault(client: firestore.Client, *, spike: bool) -> None:
    """The §9 switch and the observed rate, in the two documents `seed_firestore.py` wrote."""
    nominal = company.service(TARGET).error_rate
    client.collection("services").document(TARGET).update(
        {"error_rate": SPIKED_ERROR_RATE if spike else nominal}
    )
    client.collection("fault_injection").document(TARGET).update({"error_rate_spike": spike})


def check_result(result: incident.IncidentResult) -> int:
    """The decision half of the `verify:` line. Returns the number of failed checks."""
    failures = 0

    def fail(message: str) -> None:
        nonlocal failures
        print(f"FAIL: {message}", file=sys.stderr)
        failures += 1

    if result.outcome != "AUTHORIZED":
        fail(f"the incident ended {result.outcome}, not AUTHORIZED")
    if result.malformed_attempts:
        fail(f"the Planner needed {result.malformed_attempts} re-plan(s); expected none")

    if result.action is None:
        fail("no typed Action was produced")
        return failures
    if result.action.action_class != "ROLLBACK_CONFIG":
        fail(f"action_class is {result.action.action_class}, expected ROLLBACK_CONFIG")
    if result.action.target != TARGET:
        fail(f"target is {result.action.target}, expected {TARGET}")
    if not result.action.success_predicate.strip():
        fail("the Action declares no success predicate")

    if result.decision is None:
        fail("no decision was reached")
        return failures
    if (result.decision.outcome, result.decision.stage) != ("APPROVE", "risk"):
        fail(
            f"decision is {result.decision.outcome}/{result.decision.stage}, expected APPROVE/risk"
        )
    if result.decision.score is None:
        fail("an approved decision carries no risk arithmetic")
    else:
        score = result.decision.score
        got = (score.base, score.criticality, score.blast, score.irreversibility)
        if got != EXPECTED_COMPONENTS or score.score != EXPECTED_SCORE:
            fail(
                f"risk is {got} = {score.score}, expected {EXPECTED_COMPONENTS} = {EXPECTED_SCORE}"
            )
    try:
        gateway.verify_decision(result.decision, gateway.public_key_pem())
    except gateway.DecisionInvalid as exc:
        fail(f"the decision's signature does not verify ({exc})")
    return failures


async def run(project_id: str, private_key: ec.EllipticCurvePrivateKey) -> tuple[int, str, Any]:
    """Inject, wake the fleet, restore. Returns (failures, trace id, result)."""
    sync_client = firestore.Client(project=project_id)
    async_client = firestore.AsyncClient(project=project_id)

    switch = sync_client.collection("fault_injection").document(TARGET).get().to_dict() or {}
    if switch.get("error_rate_spike"):
        print(
            f"FAIL: fault_injection/{TARGET}.error_rate_spike is already on. Clear it first,\n"
            "      or this run's restore would write someone else's state back as baseline:\n"
            "        .venv/bin/python scripts/inject_fault.py --clear",
            file=sys.stderr,
        )
        return 1, "", None

    tracer = trace.get_tracer("provenance.verify_incident_one")
    with tracer.start_as_current_span("provenance.verify_incident_one") as root:
        trace_id = format(root.get_span_context().trace_id, "032x")
        print(f"--> injecting the fault: {TARGET} error_rate -> {SPIKED_ERROR_RATE}")
        set_fault(sync_client, spike=True)
        try:
            result = await incident.run_incident(
                incident.Trigger(
                    target=TARGET,
                    signal="error_rate",
                    observed_value=SPIKED_ERROR_RATE,
                    observed_at=OBSERVED_AT,
                ),
                client=async_client,
                planner_key=private_key,
            )
        finally:
            # Any exit path, including an exception or a Ctrl-C mid-incident (item 8).
            print("--> clearing the fault")
            set_fault(sync_client, spike=False)

    print(f"    incident {result.incident_id} -> {result.outcome}")
    if result.action is not None:
        print(f"    action    {result.action.action_class}({result.action.target})")
        print(
            f"    predicate {action.predicate_id(result.action)}  {result.action.success_predicate}"
        )
    if result.decision is not None and result.decision.score is not None:
        s = result.decision.score
        print(
            f"    risk      {s.base} + {s.criticality} + {s.blast} + {s.irreversibility} "
            f"= {s.score} -> {result.decision.outcome}"
        )
    return check_result(result), trace_id, result


def read_back(project_id: str, trace_id: str) -> list[Any]:
    """Poll until the trace stops growing, then hand whatever is there to `check_spans`.

    Waiting for the spans a *successful* incident produces would mean a failed one polls for
    the full budget and then reports "never reached Cloud Trace" -- the wrong finding, four
    minutes late. Observed: an incident that ended UNROUTABLE emits ten spans and never a
    third reasoning chain. The incident span closes last, so once it is present and the count
    has held steady across one interval the trace is as complete as it will get; `check_spans`
    is what says whether that is the right set.
    """
    client = trace_v1.TraceServiceClient()
    previous = -1
    for attempt in range(1, POLL_ATTEMPTS + 1):
        try:
            spans = list(client.get_trace(project_id=project_id, trace_id=trace_id).spans)
        except NotFound:
            spans = []
        if (
            spans
            and len(spans) == previous
            and any(s.name == telemetry.SPAN_INCIDENT for s in spans)
        ):
            return spans
        previous = len(spans)
        print(f"    {len(spans)} span(s) after {int(attempt * POLL_INTERVAL_S)}s…", flush=True)
        time.sleep(POLL_INTERVAL_S)
    return []


def attribute(labels: dict[str, str], attr: str) -> str | None:
    """The v1 API surfaces OTel attributes as `labels`, sometimes slash-prefixed. Try both."""
    return labels.get(f"/{attr}") or labels.get(attr)


def check_spans(spans: list[Any], result: Any) -> int:
    """What actually landed in Cloud Trace, which is where the `verify:` line is settled."""
    failures = 0

    def fail(message: str) -> None:
        nonlocal failures
        print(f"FAIL: {message}", file=sys.stderr)
        failures += 1

    by_name: dict[str, list[dict[str, str]]] = {}
    for span in spans:
        by_name.setdefault(span.name, []).append(dict(span.labels))

    incidents = by_name.get(telemetry.SPAN_INCIDENT, [])
    if len(incidents) != 1:
        fail(f"{len(incidents)} incident span(s) on the trace, expected exactly 1")
    else:
        labels = incidents[0]
        if attribute(labels, telemetry.ATTR_INCIDENT_OUTCOME) != "AUTHORIZED":
            fail(f"the incident span says {attribute(labels, telemetry.ATTR_INCIDENT_OUTCOME)}")
        if attribute(labels, telemetry.ATTR_INCIDENT_ROUTED_TO) != "sre-infra-agent":
            fail("the incident span does not record routing to sre-infra-agent")
        # The predicate is on the trace before anything executes -- "pre-declared", checkably.
        recorded = attribute(labels, telemetry.ATTR_INCIDENT_PREDICATE_ID)
        expected = action.predicate_id(result.action) if result.action is not None else None
        if recorded != expected:
            fail(f"the incident span's predicate_id is {recorded}, expected {expected}")
        print(f"    ok  incident span   AUTHORIZED  predicate={recorded}")

    chains = by_name.get(telemetry.SPAN_REASONING_CHAIN, [])
    steps = sorted(
        step for c in chains if (step := attribute(c, telemetry.ATTR_REASONING_STEP)) is not None
    )
    if steps != ["classification", "diagnosis", "planning"]:
        fail(f"reasoning steps on the trace are {steps}")
    else:
        print(f"    ok  reasoning spans {', '.join(steps)}")

    decisions = by_name.get(telemetry.SPAN_AUTHORIZATION_DECISION, [])
    if len(decisions) != 1:
        # "Exactly one typed proposal": a second would mean §7.1's budget was spent.
        fail(f"{len(decisions)} authorization span(s) on the trace, expected exactly 1")
        return failures

    labels = decisions[0]
    parts = [
        attribute(labels, attr)
        for attr in (
            telemetry.ATTR_RISK_BASE,
            telemetry.ATTR_RISK_CRITICALITY,
            telemetry.ATTR_RISK_BLAST,
            telemetry.ATTR_RISK_IRREVERSIBILITY,
        )
    ]
    total = attribute(labels, telemetry.ATTR_RISK_SCORE)
    if total is None or None in parts:
        fail("the authorization span's risk block is incomplete")
        return failures
    numbers = [int(p) for p in parts if p is not None]
    if tuple(numbers) != EXPECTED_COMPONENTS or int(total) != EXPECTED_SCORE:
        fail(f"the span's risk is {numbers} = {total}, expected {list(EXPECTED_COMPONENTS)} = 2")
    elif attribute(labels, telemetry.ATTR_DECISION_OUTCOME) != "APPROVE":
        fail(f"the span says {attribute(labels, telemetry.ATTR_DECISION_OUTCOME)}, not APPROVE")
    elif not attribute(labels, telemetry.ATTR_DECISION_SIGNATURE):
        fail("the authorization span carries no signature")
    else:
        print(
            f"    ok  decision span   APPROVE  risk {' + '.join(str(n) for n in numbers)} = {total}"
        )
    return failures


def check_deployed_route(url: str, token: str) -> int:
    """The trigger stream as a cold visitor meets it: guarded, and alive."""
    body = {
        "target": TARGET,
        "signal": "error_rate",
        "observed_value": SPIKED_ERROR_RATE,
        "observed_at": OBSERVED_AT,
    }
    failures = 0
    unauthenticated = httpx.post(f"{url.rstrip('/')}/trigger", json=body, timeout=30)
    if unauthenticated.status_code != 403:
        print(
            f"FAIL: /trigger answered {unauthenticated.status_code} with no token, expected 403",
            file=sys.stderr,
        )
        failures += 1
    else:
        print("    ok  deployed /trigger  403 without the shared secret")

    authenticated = httpx.post(
        f"{url.rstrip('/')}/trigger", json=body, headers={"X-Provenance-Token": token}, timeout=300
    )
    if authenticated.status_code != 200:
        print(
            f"FAIL: /trigger answered {authenticated.status_code} with the token, expected 200\n"
            f"      {authenticated.text[:300]}",
            file=sys.stderr,
        )
        failures += 1
    else:
        print(f"    ok  deployed /trigger  200 -> {authenticated.json().get('outcome')}")
    return failures


def main() -> int:
    project_id = os.environ.get("GOOGLE_CLOUD_PROJECT")
    pem = os.environ.get(incident.PLANNER_KEY_ENV)
    if not project_id:
        print("GOOGLE_CLOUD_PROJECT is not set.", file=sys.stderr)
        return 1
    if not pem:
        print(
            f"{incident.PLANNER_KEY_ENV} is not set. seed_registry.py prints each private half\n"
            "once and stores it nowhere; --rotate remediation-planner mints a new one.",
            file=sys.stderr,
        )
        return 1
    if not telemetry.configure_tracing(project_id):
        print("tracing did not configure; the spans would not be exported.", file=sys.stderr)
        return 1

    failures, trace_id, result = asyncio.run(run(project_id, load_private_key(pem)))
    if not trace_id:
        return 1
    provider = trace.get_tracer_provider()
    provider.force_flush()  # type: ignore[attr-defined]

    print(f"--> reading trace {trace_id} back from Cloud Trace (indexing takes a minute or two)")
    spans = read_back(project_id, trace_id)
    url = f"https://console.cloud.google.com/traces/list?project={project_id}&tid={trace_id}"
    if not spans:
        print("FAIL: the incident's spans never reached Cloud Trace", file=sys.stderr)
        print(url, file=sys.stderr)
        return 1
    failures += check_spans(spans, result)

    service_url = os.environ.get("PROVENANCE_SERVICE_URL")
    token = os.environ.get("PROVENANCE_TRIGGER_TOKEN")
    if service_url and token:
        print(f"--> checking the deployed trigger stream at {service_url}")
        failures += check_deployed_route(service_url, token)
    else:
        print(
            "--> SKIPPED the deployed /trigger check "
            "(set PROVENANCE_SERVICE_URL and PROVENANCE_TRIGGER_TOKEN)"
        )

    if failures:
        print(f"\n{failures} check(s) failed.\n{url}", file=sys.stderr)
        return 1
    print("\n--> one spike, one typed ROLLBACK_CONFIG, risk 2, auto-approved — by the table alone")
    print(f"    {url}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
