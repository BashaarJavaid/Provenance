#!/usr/bin/env python3
"""Check ROADMAP items 9, 10, 11 and 11.5's `verify:` lines against real GCP and real models.

    PROVENANCE_PLANNER_KEY="$(cat ~/planner.pem)" \
    GOOGLE_CLOUD_PROJECT=provenance-hackathon \
    GOOGLE_GENAI_USE_VERTEXAI=1 GOOGLE_CLOUD_LOCATION=global \
    .venv/bin/python scripts/verify_incident_one.py

Item 9's line: "the injected `inventory-api` error-rate spike produces exactly one typed
`ROLLBACK_CONFIG` proposal, risk 2, auto-approved."
Item 10's: "rollback executes on the synthetic service, error rate drops, verification returns
CONFIRMED against the predicate declared before execution."
Item 11.5's: "ten consecutive incident #1 runs all reach RESOLVED, and no run's
`success_predicate` names a threshold at or below the service's nominal error rate" -- which is
what `--runs 10` is for. Each run injects and restores around itself, because the restore is
what deletes the belief a second run would otherwise be refused for superseding, and the loop
finishes all ten even after a failure: one bad run in ten and seven in ten are different
findings, and both defects item 11.5 fixed were intermittent.

Four real Gemini calls sit between the trigger and the belief, so the point of this script is
that the *deterministic* half holds whatever the models say: the tool registry and entity model
overrule the Planner's declared fields, the risk table -- not the reasoning -- produces the 2,
and the 0.60 confidence comes from §4.3's published formula rather than from anything the
Verification Agent asserted.

This is one script rather than two because item 10 is incident #1 *finishing*. A second script
would re-inject the same fault and spend a second set of model calls re-proving item 9's half.

"Exactly one" is counted, not assumed: one `provenance.authorization.decision` span on the
trace, and zero malformed re-plans. Two proposals would mean §7.1's budget was spent.

**This script mutates stored state.** The fault injection *and the rollback it provokes* run
inside a `try/finally` that restores every field on any exit path, including Ctrl-C -- item 8's
lesson, for the same reason: a crash between the injection and the restore leaves the demo's
service permanently spiked or permanently rolled back, and `seed_firestore.py` skips existing
documents so a re-seed will not put it back. It restores exactly what it changed, and it
deletes the belief chain it wrote -- `provenance/` itself never deletes anything (§6:
append-only).

It refuses to run if the fault switch is already on, or if `beliefs/belief-inventory-api`
already exists, because in either case the restore would cement someone else's state.

Set `PROVENANCE_SERVICE_URL` and `PROVENANCE_TRIGGER_TOKEN` to also run incident #1 a second
time *through the deployed service*: 403 unauthenticated, 200 with the token, and the
`GET /trace` the trace UI reads (item 11). Skipped, loudly, without them. **That half mutates
stored state too** and takes the identical posture -- refuse against dirt, inject, restore in a
`try/finally`. It did not until this was fixed, and a clean run left the fixture at v41 with a
belief present for the next run to trip over. One honest limit: that incident runs *in the
deployed process*, so a Ctrl-C mid-trigger restores here and the remote incident can still land
its rollback afterwards. Nothing local can order those, so it warns rather than pretending.

Not run in CI: CI has no credentials and must not spend model tokens. The offline half is
`tests/test_incident.py`, which is where the malformed-retry and unroutable paths are proved,
since a real model cannot be asked to misbehave on cue.
"""

from __future__ import annotations

import argparse
import asyncio
import os
import re
import sys
import time
from typing import Any

import httpx
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from google.api_core.exceptions import NotFound
from google.cloud import firestore, trace_v1
from opentelemetry import trace

from provenance import action, beliefs, gateway, incident, policy, telemetry
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

# §4.3's arithmetic over the one thing incident #1 can honestly claim to know:
# `1 - (1 - 0.60) = 0.60` from a single fresh `verified_system_observation`.
BELIEF_ID = f"belief-{TARGET}"
EXPECTED_CONFIDENCE = 0.60

# Item 11.5's second `verify:` clause: "no run's success_predicate names a threshold at or
# below the service's nominal error rate". A percentage, or a bare decimal below 1 -- so
# "below 0.5% within 10 minutes, config version v41" yields [0.005] and not [0.005, 10, 41].
# Deliberately here and not in `provenance/`: the fix upstream is a prompt clause, and a regex
# over natural language on the production path would spend §7.1's single retry budget on a
# failure that is not a schema failure. Here the worst it can do is print.
_THRESHOLD = re.compile(r"(\d+(?:\.\d+)?)\s*%|\b(0\.\d+)\b")


def thresholds(predicate: str) -> list[float]:
    """Every rate the sentence names, normalised to a fraction."""
    found: list[float] = []
    for percent, decimal in _THRESHOLD.findall(predicate):
        found.append(float(percent) / 100 if percent else float(decimal))
    return found


def load_private_key(pem: str) -> ec.EllipticCurvePrivateKey:
    key = serialization.load_pem_private_key(pem.encode(), password=None)
    if not isinstance(key, ec.EllipticCurvePrivateKey):
        raise TypeError("PROVENANCE_PLANNER_KEY is not an EC private key")
    return key


def inject(client: firestore.Client) -> None:
    """The §9 switch and the observed rate, in the two documents `seed_firestore.py` wrote."""
    client.collection("services").document(TARGET).update(
        {"error_rate": SPIKED_ERROR_RATE, "healthy": False}
    )
    client.collection("fault_injection").document(TARGET).update({"error_rate_spike": True})


def restore(client: firestore.Client) -> None:
    """Put back every field this run could have moved, from the in-code fixture, not from memory.

    Item 10 widened this from item 9's one-field clear: the rollback the fleet performs writes
    `current_config_version` and `healthy` too, and the Policy Engine writes a belief. What is
    restored is exactly the demo baseline `seed_firestore.py --reset` would write, plus a
    delete of the one belief document this script's incident can have created.

    The delete lives here rather than in `policy.py`: §6 makes beliefs append-only and the
    engine has no delete path at all. Tearing down a *test fixture* is a different act from
    retracting a belief (§6.4), and only one of them belongs in the product.

    Item 12 widened the belief half from one document to a chain: the version subcollection,
    the `evidence/{id}` documents those versions cite, and the root document.
    """
    service = company.service(TARGET)
    client.collection("services").document(TARGET).update(
        {
            "error_rate": service.error_rate,
            "healthy": service.healthy,
            "current_config_version": service.current_config_version,
        }
    )
    client.collection("fault_injection").document(TARGET).update({"error_rate_spike": False})
    delete_belief(client)


def delete_belief(client: firestore.Client) -> None:
    """Remove the whole chain this run's incident can have written, evidence included.

    The evidence ids are read off the version documents rather than reconstructed: each is
    `ev-{predicate_id}`, and the predicate is whatever the Planner wrote this run.
    """
    versions = client.collection(f"{beliefs.COLLECTION}/{BELIEF_ID}/versions")
    for snapshot in versions.stream():
        for evidence_id in (snapshot.to_dict() or {}).get("evidence", []):
            client.collection(beliefs.EVIDENCE_COLLECTION).document(evidence_id).delete()
        snapshot.reference.delete()
    client.collection(beliefs.COLLECTION).document(BELIEF_ID).delete()


def refuse_if_dirty(client: firestore.Client) -> bool:
    """True if live state is already dirty. Prints which condition, and how to clear it.

    Item 8's precedent: refuse rather than cement. Both halves of this script inject and
    restore, so both call this -- a restore over somebody else's state writes their state
    back as the baseline, which is worse than the run simply not happening.
    """
    switch = client.collection("fault_injection").document(TARGET).get().to_dict() or {}
    if switch.get("error_rate_spike"):
        print(
            f"FAIL: fault_injection/{TARGET}.error_rate_spike is already on. Clear it first,\n"
            "      or this run's restore would write someone else's state back as baseline:\n"
            "        .venv/bin/python scripts/inject_fault.py --clear",
            file=sys.stderr,
        )
        return True
    if client.collection(beliefs.COLLECTION).document(BELIEF_ID).get().exists:
        # Since item 12 a pre-existing v1 no longer refuses the run -- it would be superseded,
        # which is correct behaviour and would still make this script's v1 assertion fail. The
        # reason to refuse is unchanged: the restore would delete somebody else's chain.
        print(
            f"FAIL: {beliefs.COLLECTION}/{BELIEF_ID} already exists. This run would supersede\n"
            "      it, and its restore would then delete that whole chain.\n"
            "      Remove it deliberately, then re-run.",
            file=sys.stderr,
        )
        return True
    return False


def check_result(result: incident.IncidentResult) -> int:
    """The decision half of the `verify:` line. Returns the number of failed checks."""
    failures = 0

    def fail(message: str) -> None:
        nonlocal failures
        print(f"FAIL: {message}", file=sys.stderr)
        failures += 1

    if result.outcome != "RESOLVED":
        fail(f"the incident ended {result.outcome}, not RESOLVED")
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
    else:
        # Item 11.5. A successful rollback writes the nominal rate back verbatim, so a
        # threshold *at* it is unsatisfiable and REFUTED is the honest answer to it. The bug
        # that produced that was upstream of verification, and this is where it is caught.
        nominal = company.service(TARGET).error_rate
        named = thresholds(result.action.success_predicate)
        if not named:
            print(f"WARN: no numeric threshold parsed out of {result.action.success_predicate!r}")
        for value in named:
            if value <= nominal:
                fail(
                    f"the predicate names {value}, at or below the nominal error rate "
                    f"{nominal}; a fully successful rollback could not satisfy it"
                )

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

    # --- item 10: it executed, it dropped, it was confirmed, and it was learned from.
    if result.execution is None:
        fail("the approved rollback never executed")
    elif (result.execution.from_version, result.execution.to_version) != ("v42", "v41"):
        fail(
            f"the rollback went {result.execution.from_version} -> "
            f"{result.execution.to_version}, expected v42 -> v41"
        )
    if result.verification != "CONFIRMED":
        fail(f"verification returned {result.verification}, expected CONFIRMED")

    if result.belief is None:
        fail("a CONFIRMED verification wrote no belief")
        return failures
    if (result.belief.outcome, result.belief.reason) != ("COMMIT", "ABOVE_THRESHOLD"):
        fail(f"the belief is {result.belief.outcome}/{result.belief.reason}, expected COMMIT")
    if abs(result.belief.confidence - EXPECTED_CONFIDENCE) > 1e-6:
        # Not "roughly right": §4.3 is a published formula over one fresh observation, so the
        # only honest expectation is the exact number it produces.
        fail(f"confidence is {result.belief.confidence}, expected {EXPECTED_CONFIDENCE}")
    try:
        policy.verify_commit(result.belief, policy.public_key_pem())
    except policy.CommitInvalid as exc:
        fail(f"the belief commit's signature does not verify ({exc})")
    return failures


def check_post_state(client: firestore.Client) -> int:
    """The `verify:` line's middle clause, read back out of Firestore before the restore runs.

    `result.execution` says what the executor believed it did; this says what the store holds.
    """
    failures = 0
    state = client.collection("services").document(TARGET).get().to_dict() or {}
    nominal = company.service(TARGET).error_rate
    if state.get("current_config_version") != "v41":
        print(
            f"FAIL: {TARGET} is on {state.get('current_config_version')}, expected v41",
            file=sys.stderr,
        )
        failures += 1
    if state.get("error_rate") != nominal:
        print(
            f"FAIL: {TARGET} error_rate is {state.get('error_rate')}, expected {nominal}",
            file=sys.stderr,
        )
        failures += 1
    if not failures:
        print(f"    ok  post-state      v41, error_rate {nominal} (from {SPIKED_ERROR_RATE})")
    return failures


async def run(project_id: str, private_key: ec.EllipticCurvePrivateKey) -> tuple[int, str, Any]:
    """Inject, wake the fleet, restore. Returns (failures, trace id, result)."""
    sync_client = firestore.Client(project=project_id)
    async_client = firestore.AsyncClient(project=project_id)

    if refuse_if_dirty(sync_client):
        return 1, "", None

    tracer = trace.get_tracer("provenance.verify_incident_one")
    with tracer.start_as_current_span("provenance.verify_incident_one") as root:
        trace_id = format(root.get_span_context().trace_id, "032x")
        print(f"--> injecting the fault: {TARGET} error_rate -> {SPIKED_ERROR_RATE}")
        inject(sync_client)
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
            # Read the store *before* the restore puts v42 back: this is the only window in
            # which the rolled-back state exists, and it is half the `verify:` line.
            post_failures = check_post_state(sync_client)
        finally:
            # Any exit path, including an exception or a Ctrl-C mid-incident (item 8). Item 10
            # widened it: the fleet now writes three service fields and a belief.
            print("--> restoring: v42, nominal error rate, fault off, belief deleted")
            restore(sync_client)

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
    if result.execution is not None:
        print(
            f"    executed  {result.execution.from_version} -> {result.execution.to_version}"
            f"  verification {result.verification}"
        )
    if result.belief is not None:
        print(
            f"    belief    {result.belief.belief_id} v{result.belief.version} "
            f"{result.belief.outcome} at confidence {result.belief.confidence:.2f}"
        )
    return check_result(result) + post_failures, trace_id, result


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
        before = failures
        outcome = attribute(labels, telemetry.ATTR_INCIDENT_OUTCOME)
        if outcome != "RESOLVED":
            fail(f"the incident span says {outcome}")
        if attribute(labels, telemetry.ATTR_INCIDENT_ROUTED_TO) != "sre-infra-agent":
            fail("the incident span does not record routing to sre-infra-agent")
        # The predicate is on the trace before anything executes -- "pre-declared", checkably.
        recorded = attribute(labels, telemetry.ATTR_INCIDENT_PREDICATE_ID)
        expected = action.predicate_id(result.action) if result.action is not None else None
        if recorded != expected:
            fail(f"the incident span's predicate_id is {recorded}, expected {expected}")
        # Only claim ok if nothing above failed: this line used to print a hardcoded
        # "RESOLVED" unconditionally, so a failing run reported success beside its own FAIL.
        if failures == before:
            print(f"    ok  incident span   {outcome}  predicate={recorded}")

    chains = by_name.get(telemetry.SPAN_REASONING_CHAIN, [])
    steps = sorted(
        step for c in chains if (step := attribute(c, telemetry.ATTR_REASONING_STEP)) is not None
    )
    if steps != ["classification", "diagnosis", "planning", "verification"]:
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

    failures += check_learning_spans(by_name, incidents)
    return failures


def check_learning_spans(
    by_name: dict[str, list[dict[str, str]]], incidents: list[dict[str, str]]
) -> int:
    """Item 10's two spans: what verification concluded, and what memory did about it.

    The `predicate_id` comparison is the one that matters. The incident span carried that hash
    before the executor ran and the verification span carries it after, so matching them is how
    the *trace* -- not a docstring -- says the predicate was declared before execution.
    """
    failures = 0

    def fail(message: str) -> None:
        nonlocal failures
        print(f"FAIL: {message}", file=sys.stderr)
        failures += 1

    verifications = by_name.get(telemetry.SPAN_VERIFICATION_OUTCOME, [])
    if len(verifications) != 1:
        fail(f"{len(verifications)} verification span(s) on the trace, expected exactly 1")
    else:
        labels = verifications[0]
        outcome = attribute(labels, telemetry.ATTR_VERIFICATION_OUTCOME)
        written = attribute(labels, telemetry.ATTR_VERIFICATION_BELIEF_WRITTEN)
        predicate = attribute(labels, telemetry.ATTR_VERIFICATION_PREDICATE_ID)
        declared = (
            attribute(incidents[0], telemetry.ATTR_INCIDENT_PREDICATE_ID) if incidents else None
        )
        if outcome != "CONFIRMED":
            fail(f"the verification span says {outcome}, expected CONFIRMED")
        elif str(written).lower() != "true":
            fail(f"a CONFIRMED verification recorded belief_written={written}")
        elif predicate != declared:
            fail(
                f"the verification span's predicate_id is {predicate}, but the incident span "
                f"declared {declared} before execution"
            )
        else:
            print(f"    ok  verification    CONFIRMED  predicate={predicate}  belief written")

    beliefs = by_name.get(telemetry.SPAN_BELIEF_COMMIT, [])
    if len(beliefs) != 1:
        fail(f"{len(beliefs)} belief.commit span(s) on the trace, expected exactly 1")
        return failures

    labels = beliefs[0]
    outcome = attribute(labels, telemetry.ATTR_DECISION_OUTCOME)
    confidence = attribute(labels, telemetry.ATTR_BELIEF_CONFIDENCE)
    if outcome != "COMMIT":
        fail(f"the belief span says {outcome}/{attribute(labels, telemetry.ATTR_DECISION_REASON)}")
    elif confidence is None or abs(float(confidence) - EXPECTED_CONFIDENCE) > 1e-6:
        fail(f"the belief span's confidence is {confidence}, expected {EXPECTED_CONFIDENCE}")
    elif not attribute(labels, telemetry.ATTR_DECISION_SIGNATURE):
        fail("the belief.commit span carries no signature")
    elif attribute(labels, telemetry.ATTR_BELIEF_SUPERSEDES) is not None:
        # A first belief supersedes nothing, and the stub cannot write the link a v2 needs.
        fail("a first belief carries a supersedes attribute")
    else:
        print(
            f"    ok  belief span     COMMIT  {attribute(labels, telemetry.ATTR_BELIEF_ID)} "
            f"at confidence {confidence}"
        )
    return failures


def check_deployed_route(url: str, token: str, client: firestore.Client) -> int:
    """The trigger stream as a cold visitor meets it: guarded, alive, and a *real* incident.

    **This mutates stored state**, and for the same reason the local half does: the incident it
    wakes rolls the service back and writes a belief. It therefore takes the same three-part
    posture -- refuse against dirt, inject, restore in a `try/finally`. It did not until this
    was fixed, and a clean run left the fixture stranded at v41 with a belief present, which
    the *next* run's precondition check would then refuse over.

    Injecting matters beyond tidiness. Before, this ran after `run()`'s restore had already put
    the baseline back, so it woke the fleet against a nominal service with nothing to diagnose
    -- four model calls to reach ESCALATED/INCONCLUSIVE and assert almost nothing. Now it is
    incident #1, end to end, through Cloud Run.
    """
    body = {
        "target": TARGET,
        "signal": "error_rate",
        "observed_value": SPIKED_ERROR_RATE,
        "observed_at": OBSERVED_AT,
    }
    failures = 0

    # First, because it touches no state and spends nothing.
    unauthenticated = httpx.post(f"{url.rstrip('/')}/trigger", json=body, timeout=30)
    if unauthenticated.status_code != 403:
        print(
            f"FAIL: /trigger answered {unauthenticated.status_code} with no token, expected 403",
            file=sys.stderr,
        )
        failures += 1
    else:
        print("    ok  deployed /trigger  403 without the shared secret")

    if refuse_if_dirty(client):
        return failures + 1

    print(
        f"--> injecting the fault for the deployed run: {TARGET} error_rate -> {SPIKED_ERROR_RATE}"
    )
    inject(client)
    completed = False
    try:
        authenticated = httpx.post(
            f"{url.rstrip('/')}/trigger",
            json=body,
            headers={"X-Provenance-Token": token},
            timeout=300,
        )
        if authenticated.status_code != 200:
            print(
                f"FAIL: /trigger answered {authenticated.status_code} with the token, expected"
                f" 200\n      {authenticated.text[:300]}",
                file=sys.stderr,
            )
            return failures + 1
        outcome = str(authenticated.json().get("outcome"))
        print(f"    ok  deployed /trigger  200 -> {outcome}")
        # Deliberately not asserting RESOLVED here: until item 11.5 lands the Planner can write
        # a predicate a successful rollback cannot satisfy, and failing this half over that
        # would report one defect twice. `check_result` is where that assertion lives.
        failures += check_deployed_trace(url, outcome)
        completed = True
    finally:
        # Covers the ~60s trigger itself, not just the assertions after it -- a Ctrl-C in that
        # window is the exact case that stranded the fixture.
        print("--> restoring: v42, nominal error rate, fault off, belief deleted")
        restore(client)
        if not completed:
            # The limit of a local `try/finally` when the writer is remote. Verified, not
            # assumed: a SIGINT 25s into the trigger restores correctly here, and the Cloud Run
            # incident then finishes and writes `current_config_version: v41` *after* the
            # restore. Nothing in this process can order those two, so say so rather than
            # report a clean exit over a fixture that is about to go dirty.
            print(
                f"WARNING: the deployed incident may still be running and can write {TARGET}\n"
                "         after this restore. Re-check the fixture in a minute, and clear it:\n"
                "           .venv/bin/python scripts/inject_fault.py --clear",
                file=sys.stderr,
            )
    return failures


# What each incident outcome guarantees reached the stream. Deriving this rather than
# demanding all five matters: `run()` above restores the fault switch before this runs, so
# the deployed trigger wakes the fleet against a *healthy* service and legitimately produces
# a shorter incident. Asserting five shapes regardless would fail on a correct system.
_SHAPES_IMPLIED_BY = {
    "RESOLVED": (
        telemetry.SPAN_INCIDENT,
        telemetry.SPAN_REASONING_CHAIN,
        telemetry.SPAN_AUTHORIZATION_DECISION,
        telemetry.SPAN_VERIFICATION_OUTCOME,
        telemetry.SPAN_BELIEF_COMMIT,
    ),
    "ESCALATED": (telemetry.SPAN_INCIDENT, telemetry.SPAN_REASONING_CHAIN),
    "AUTHORIZED": (
        telemetry.SPAN_INCIDENT,
        telemetry.SPAN_REASONING_CHAIN,
        telemetry.SPAN_AUTHORIZATION_DECISION,
    ),
    "HELD": (
        telemetry.SPAN_INCIDENT,
        telemetry.SPAN_REASONING_CHAIN,
        telemetry.SPAN_AUTHORIZATION_DECISION,
    ),
    "DENIED": (
        telemetry.SPAN_INCIDENT,
        telemetry.SPAN_REASONING_CHAIN,
        telemetry.SPAN_AUTHORIZATION_DECISION,
    ),
    "UNROUTABLE": (telemetry.SPAN_INCIDENT, telemetry.SPAN_REASONING_CHAIN),
}


def check_deployed_trace(url: str, outcome: str) -> int:
    """Item 11: what the trace UI reads, checked as a cold browser meets it -- no token.

    This runs straight after the deployed trigger returned, so the incident it just ran is
    the newest trace in the buffer. Three properties, all of them things a rendered panel
    would be lying about if they failed.
    """
    failures = 0
    response = httpx.get(f"{url.rstrip('/')}/trace", timeout=30)
    if response.status_code != 200:
        print(
            f"FAIL: /trace answered {response.status_code} with no token, expected 200",
            file=sys.stderr,
        )
        return 1
    spans = response.json()
    if not spans:
        print("FAIL: /trace served nothing after an incident ran", file=sys.stderr)
        return 1
    print("    ok  deployed /trace    200 without a token (a cold browser can watch)")

    # One incident is one trace; the UI renders the newest, so that is what is asserted on.
    newest = max(spans, key=lambda span: span["start_ns"])["trace_id"]
    trace_spans = [span for span in spans if span["trace_id"] == newest]
    shapes = {span["name"] for span in trace_spans}
    expected = _SHAPES_IMPLIED_BY.get(outcome, _SHAPES_IMPLIED_BY["UNROUTABLE"])
    missing = set(expected) - shapes
    if missing:
        print(
            f"FAIL: a {outcome} incident should have reached the stream as "
            f"{sorted(expected)}; /trace is missing {sorted(missing)}",
            file=sys.stderr,
        )
        failures += 1
    else:
        print(
            f"    ok  deployed /trace    {len(expected)} shapes a {outcome} incident implies, "
            f"on trace {newest[:16]}..."
        )

    # The ledger renders this arithmetic; telemetry.set_risk() refuses to emit a score that
    # is not its components' sum, so a mismatch here means the panel is rendering a fiction.
    for span in trace_spans:
        if span["name"] != telemetry.SPAN_AUTHORIZATION_DECISION:
            continue
        attrs = span["attrs"]
        if telemetry.ATTR_RISK_SCORE not in attrs:
            continue
        components = sum(
            attrs[key]
            for key in (
                telemetry.ATTR_RISK_BASE,
                telemetry.ATTR_RISK_CRITICALITY,
                telemetry.ATTR_RISK_BLAST,
                telemetry.ATTR_RISK_IRREVERSIBILITY,
            )
        )
        if components != attrs[telemetry.ATTR_RISK_SCORE]:
            print(
                f"FAIL: /trace served score {attrs[telemetry.ATTR_RISK_SCORE]} over "
                f"components summing to {components}",
                file=sys.stderr,
            )
            failures += 1
        else:
            print(
                f"    ok  deployed /trace    risk {attrs[telemetry.ATTR_RISK_SCORE]} = its components"
            )

    # §8.1's redaction rule, checked on the bytes a public endpoint actually serves.
    forbidden = ("prompt", "rationale", "payload", "text", "content", "message", "body")
    leaked = sorted(
        key
        for span in trace_spans
        for key in span["attrs"]
        if any(part in key for part in forbidden)
    )
    if leaked:
        print(f"FAIL: /trace served content-bearing attributes: {leaked}", file=sys.stderr)
        failures += 1
    else:
        print("    ok  deployed /trace    identifiers, hashes, enums and numbers only")
    return failures


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--runs",
        type=int,
        default=1,
        metavar="N",
        help=(
            "how many consecutive incidents to run (item 11.5's `verify:` line is 10). "
            "Each one injects and restores around itself, because the restore is what "
            "deletes the belief a second run would otherwise be refused for superseding."
        ),
    )
    args = parser.parse_args()
    if args.runs < 1:
        print("--runs must be at least 1.", file=sys.stderr)
        return 1

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

    private_key = load_private_key(pem)
    failures = 0
    resolved = 0
    predicates: list[str] = []
    for attempt in range(1, args.runs + 1):
        if args.runs > 1:
            print(f"\n=== run {attempt}/{args.runs} " + "=" * 48)
        # Every run restores itself, so a failure strands nothing and the loop keeps going:
        # "1 of 10 bad" and "7 of 10 bad" are different findings, and both defects item 11.5
        # fixes were intermittent. Stopping at the first would not tell them apart.
        run_failures, trace_id, result = asyncio.run(run(project_id, private_key))
        failures += run_failures
        if not trace_id:
            return 1
        if result is not None:
            resolved += result.outcome == "RESOLVED"
            if result.action is not None:
                predicates.append(result.action.success_predicate)

    if args.runs > 1:
        print(f"\n--> {resolved}/{args.runs} runs reached RESOLVED. The predicates declared:")
        for index, predicate in enumerate(predicates, start=1):
            print(f"    {index:2}. {predicate}")
        named = [value for predicate in predicates for value in thresholds(predicate)]
        if named:
            print(
                f"    lowest threshold named: {min(named)} "
                f"against a nominal {company.service(TARGET).error_rate}"
            )
        if resolved != args.runs:
            print(f"FAIL: {resolved}/{args.runs} reached RESOLVED, expected all", file=sys.stderr)
            failures += 1
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
        # One client, built where the project id was already resolved.
        failures += check_deployed_route(service_url, token, firestore.Client(project=project_id))
    else:
        print(
            "--> SKIPPED the deployed /trigger check "
            "(set PROVENANCE_SERVICE_URL and PROVENANCE_TRIGGER_TOKEN)"
        )

    if failures:
        print(f"\n{failures} check(s) failed.\n{url}", file=sys.stderr)
        return 1
    print(
        "\n--> one spike, one typed ROLLBACK_CONFIG, risk 2, auto-approved by the table alone;"
        "\n    executed, CONFIRMED against the predicate declared before it ran, and one belief"
        "\n    committed at 0.60 — by the published formula, not by anything a model asserted"
    )
    print(f"    {url}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
