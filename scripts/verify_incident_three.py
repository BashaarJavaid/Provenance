#!/usr/bin/env python3
"""Check ROADMAP item 24's `verify:` line against real Firestore and real Gemini.

    PROVENANCE_PLANNER_KEY="$(cat ~/planner.pem)" \
    GOOGLE_CLOUD_PROJECT=provenance-hackathon \
    GOOGLE_GENAI_USE_VERTEXAI=1 GOOGLE_CLOUD_LOCATION=global \
    .venv/bin/python scripts/verify_incident_three.py

The line: "the trace shows the class-belief nomination on an entity with zero entity beliefs."
Item 23 proved the *mechanism* -- `verify_class_belief.py` already shows a real
`text-embedding-005` nominating `belief-service.tier2` for exactly this `pricing-api` query
with `recalled.entity_ids == ()`. What had never run is the **fleet**: an incident that wakes
on that service, is routed, and diagnoses with the generalization as the only thing in memory.

**The incident ends `ESCALATED`, and that is the design rather than a shortfall.**
`pricing-api` has `known_good_version=None` on purpose (`company.py`, ADR-025 reason 12), so
`executor.execute()` refuses -- §7.3's fail-closed posture, already built and already tested --
and `incident.py`'s execute node routes `HALT`. The fleet generalized correctly, proposed the
right *class* of remediation, and the executor declined an action the entity cannot receive.
Nothing verifies, so §7.2 permits nothing to be learned, so `pricing-api` stays belief-free --
which is the premise every later run of this beat depends on. Reasoning in ADR-026.

The half that would silently pass on a broken fleet is the hypothesis. The SRE agent's built-in
config hint is conditioned on "the deployed config version is ahead of the last known-good one"
and that precondition is **false** here -- both are `unknown` -- so unlike incident #2 the hint
cannot be what produced `config_regression`. That is stated as what it is: strictly stronger
than item 18 could claim, and still not a measurement. Item 32's `--memory-disabled` A/B owns
the number, and one paired live run would be an anecdote.

`--runs N` runs the incident N consecutive times, tallying how many selected a config cause and
printing every hypothesis. Item 11.5's reason: this beat is thirty seconds of video, one live
run says nothing about a flake rate, and both defects item 11.5 fixed were intermittent. The
Cloud Trace read-back runs on the last run only -- each one polls up to four minutes.

**Writes live state**, so `refuse_if_dirty()` before and a `try/finally` restore after, per run.
Two invariants no other script asserts sit in that teardown: `belief-pricing-api` must not
exist on exit, and the class belief's own chain must be byte-identical from start to finish --
`verify_supply_chain.py`'s guard on `SUP-042`, for the same reason.

Costs three `gemini-2.5-pro` calls and one embedding batch per run; no Flash call, because the
Verification Agent is never reached and that is itself checked. ~45s. Needs credentials, so not
in CI; the offline half is `tests/test_incident.py`'s item-24 cases.
"""

from __future__ import annotations

import argparse
import asyncio
import os
import sys
from dataclasses import asdict
from typing import Any

from cryptography.hazmat.primitives.asymmetric import ec
from google.cloud import firestore
from opentelemetry import trace

# Only the target-agnostic half of incident #1's script. Everything else there closes over its
# own `TARGET = "inventory-api"`, so the state helpers below are local rather than imported:
# item 19's "two restore paths over one fixture drift" is an argument about *one* fixture, and
# this is a different one. `SWITCHES` is imported for the reason it exists -- a teardown that
# knew about fewer switches than §9 has would leave one on.
from verify_incident_one import SWITCHES, attribute, load_private_key, read_back

from provenance import audit, beliefs, incident, telemetry
from provenance.agents import sre_infra
from provenance.synthetic import company

TARGET = "pricing-api"
BELIEF_ID = beliefs.belief_id_for(TARGET)
# Byte-identical to the query item 23 measured the nomination against, so the recall half of
# this run is a known quantity rather than a fresh measurement: `SIMILARITY_FLOOR` was
# calibrated on this query shape (ADR-020) and the observed value is part of the embedded text.
SPIKED_ERROR_RATE = 0.38
OBSERVED_AT = "2026-08-25T11:20:00Z"

# §4.2 on a tier-2, reversible, single-service rollback: base 1 + tier2 1 + service 0 +
# reversible 0 = 2, and 0-3 is APPROVE. The same arithmetic incident #1 reaches, which is the
# point -- nothing about a cold entity changes what the gateway does.
EXPECTED_COMPONENTS = (1, 1, 0, 0)
EXPECTED_SCORE = 2


def inject(client: firestore.Client) -> None:
    """The §9 switch and the observed rate, in the two documents `seed_firestore.py` wrote."""
    client.collection("services").document(TARGET).update(
        {"error_rate": SPIKED_ERROR_RATE, "healthy": False}
    )
    client.collection("fault_injection").document(TARGET).update({"error_rate_spike": True})


def authorizations_for_target(client: firestore.Client) -> list[Any]:
    """Every ledger record this target has (item 15), queried by target rather than by id.

    The id is derived from the decision signature and the gateway's signing key is per process,
    so a run cannot reconstruct the id of a record an earlier run wrote.
    """
    return list(
        client.collection(audit.COLLECTION)
        .where(filter=firestore.FieldFilter("target", "==", TARGET))
        .stream()
    )


def delete_belief(client: firestore.Client) -> None:
    """The whole chain, evidence included. Defensive: this incident cannot write one."""
    versions = client.collection(f"{beliefs.COLLECTION}/{BELIEF_ID}/versions")
    for snapshot in versions.stream():
        for evidence_id in (snapshot.to_dict() or {}).get("evidence", []):
            client.collection(beliefs.EVIDENCE_COLLECTION).document(evidence_id).delete()
        snapshot.reference.delete()
    client.collection(beliefs.COLLECTION).document(BELIEF_ID).delete()


def restore(client: firestore.Client) -> int:
    """Put back every field this run could have moved, and check the one that must not have.

    Returns a failure count rather than nothing, because the belief check *is* an assertion:
    `pricing-api` has to stay belief-free or every later run of this beat proves nothing, and
    the only place to see that is after the run and before the delete. The delete still happens
    either way, so a surprise cannot strand the next run.
    """
    service = company.service(TARGET)
    client.collection("services").document(TARGET).update(
        {
            "error_rate": service.error_rate,
            "healthy": service.healthy,
            "current_config_version": service.current_config_version,
        }
    )
    client.collection("fault_injection").document(TARGET).update(dict.fromkeys(SWITCHES, False))

    failures = 0
    if client.collection(beliefs.COLLECTION).document(BELIEF_ID).get().exists:
        print(
            f"FAIL: {beliefs.COLLECTION}/{BELIEF_ID} exists. Nothing executed, so §7.2 permits\n"
            "      nothing to be learned -- a belief here means the loop committed on an\n"
            "      unverified action. Deleting it so the next run is not blocked.",
            file=sys.stderr,
        )
        failures += 1
        delete_belief(client)
    for snapshot in authorizations_for_target(client):
        snapshot.reference.delete()
    return failures


def refuse_if_dirty(client: firestore.Client) -> bool:
    """True if live state is already dirty. Item 8's precedent: refuse rather than cement."""
    switch = client.collection("fault_injection").document(TARGET).get().to_dict() or {}
    already_on = [name for name in SWITCHES if switch.get(name)]
    if already_on:
        print(
            f"FAIL: fault_injection/{TARGET} already has {', '.join(already_on)} on. Clear it\n"
            "      first, or this run's restore would write someone else's state back as\n"
            "      baseline:\n"
            f"        .venv/bin/python scripts/inject_fault.py --target {TARGET} --clear",
            file=sys.stderr,
        )
        return True
    if client.collection(beliefs.COLLECTION).document(BELIEF_ID).get().exists:
        print(
            f"FAIL: {beliefs.COLLECTION}/{BELIEF_ID} already exists, so {TARGET} is not the\n"
            "      entity with empty memory this item is about. Remove it deliberately,\n"
            "      then re-run.",
            file=sys.stderr,
        )
        return True
    existing = authorizations_for_target(client)
    if existing:
        print(
            f"FAIL: {audit.COLLECTION} already holds {len(existing)} record(s) for {TARGET}.\n"
            "      This run's restore deletes every one of them, so somebody else's audit\n"
            "      trail would go with it. Remove them deliberately, then re-run.",
            file=sys.stderr,
        )
        return True
    return False


async def the_class_belief(client: firestore.AsyncClient) -> str:
    """The one CLASS belief in the store, found through the index rather than by a name here.

    `seed_class_belief.py` lets the Analyst write the class name, so hard-coding it would make
    this script pass or fail on what a model chose to call it. Same reason as
    `verify_class_belief.py`, and the same lookup.
    """
    indexed = [belief_id for belief_id, _ in await beliefs.class_statements(client=client)]
    if len(indexed) != 1:
        raise SystemExit(
            f"expected exactly one class belief in the store, found {indexed}. "
            "Run scripts/seed_class_belief.py first."
        )
    return indexed[0]


def check_result(result: incident.IncidentResult) -> int:
    """Everything the run must have produced, and everything the halt implies it must not."""
    failures = 0

    def fail(message: str) -> None:
        nonlocal failures
        failures += 1
        print(f"  FAIL {message}")

    print(f"--> incident {result.incident_id}: {result.outcome}")

    if result.outcome != "ESCALATED":
        fail(f"outcome is {result.outcome}, expected ESCALATED")

    proposed = result.action
    if proposed is None:
        fail("no typed Action was produced -- the fleet never got as far as proposing")
    else:
        print(f"    action: {proposed.action_class}({proposed.target})")
        print(f"    success_predicate: {proposed.success_predicate!r}")
        if (proposed.action_class, proposed.target) != ("ROLLBACK_CONFIG", TARGET):
            fail(f"action is {proposed.action_class}({proposed.target})")

    decision = result.decision
    if decision is None:
        fail("no decision -- the proposal never reached the gateway")
    else:
        print(f"    decision: {decision.outcome} at stage {decision.stage}")
        if (decision.outcome, decision.stage) != ("APPROVE", "risk"):
            fail(f"decision is {decision.outcome} at {decision.stage}, expected APPROVE at risk")
        score = decision.score
        if score is None:
            fail("an approved decision carries no risk score")
        else:
            components = (score.base, score.criticality, score.blast, score.irreversibility)
            print(f"    risk: {' + '.join(str(c) for c in components)} = {score.score}")
            if components != EXPECTED_COMPONENTS or score.score != EXPECTED_SCORE:
                fail(f"risk is {components} = {score.score}, expected {EXPECTED_COMPONENTS} = 2")
            if sum(components) != score.score:
                fail(f"risk components {components} do not sum to {score.score}")

    # §7.2 with no branch to check: the executor refused, so nothing ran, nothing was verified
    # and nothing was learned. All three have to be absent -- "no belief" alone would also be
    # true of a loop that executed and then quietly skipped its own commit.
    for name, value in (
        ("execution", result.execution),
        ("verification", result.verification),
        ("belief", result.belief),
    ):
        if value is not None:
            fail(f"{name} is {value!r}, but the executor refused this action")
    if result.malformed_attempts:
        fail(f"{result.malformed_attempts} malformed re-plan(s); §7.1's budget was spent")

    return failures


def check_live_spans(class_belief_id: str) -> tuple[int, str]:
    """The verify line itself, off the in-process span buffer. Returns (failures, hypothesis).

    The buffer rather than Cloud Trace because a `--runs 10` sweep would otherwise pay ten
    four-minute polls to read the same three attributes. It is the *same span objects* Cloud
    Trace gets (item 11), not a copy, so nothing is weakened by reading them here; the durable
    read-back below still runs once and checks the shapes.
    """
    failures = 0

    def fail(message: str) -> None:
        nonlocal failures
        failures += 1
        print(f"  FAIL {message}")

    by_step: dict[str, dict[str, Any]] = {}
    for span in telemetry.BUFFER.snapshot():
        if span["name"] != telemetry.SPAN_REASONING_CHAIN:
            continue
        attrs = span["attrs"]
        assert isinstance(attrs, dict)
        by_step[str(attrs.get(telemetry.ATTR_REASONING_STEP, ""))] = span

    classification = by_step.get("classification")
    diagnosis = by_step.get("diagnosis")
    if classification is None or diagnosis is None:
        fail(f"reasoning steps are {sorted(by_step)}, expected classification and diagnosis")
        return failures, ""

    attrs = classification["attrs"]
    assert isinstance(attrs, dict)
    nominated = list(attrs.get(telemetry.ATTR_RECALL_NOMINATED_IDS) or ())
    survived = list(attrs.get(telemetry.ATTR_RECALL_BELIEF_IDS) or ())
    print(f"    recall: nominated {nominated}, handed over {survived}")
    if class_belief_id not in nominated:
        fail(f"the index nominated {nominated}, missing {class_belief_id}")
    if class_belief_id not in survived:
        fail(f"the store handed over {survived}, missing {class_belief_id}")
    # The literal verify line: a class-belief nomination on an entity with *zero* entity
    # beliefs. Without this the same trace would be produced by a warm entity.
    if BELIEF_ID in survived:
        fail(f"{BELIEF_ID} is in {survived}; {TARGET} was supposed to have no entity beliefs")

    if not classification["start_ns"] < diagnosis["start_ns"]:  # type: ignore[operator]
        fail("the classification span did not start before the diagnosis span")

    attrs = diagnosis["attrs"]
    assert isinstance(attrs, dict)
    hypothesis = str(attrs.get(telemetry.ATTR_REASONING_SELECTED_HYPOTHESIS, ""))
    considered = attrs.get(telemetry.ATTR_REASONING_HYPOTHESES_CONSIDERED)
    print(f"    diagnosis: {hypothesis!r} out of {considered} considered")
    # A FAIL and not a WARN. It does **not** claim memory caused the choice -- but unlike
    # incident #2 it cannot have been the SRE prompt's own hint either, whose precondition
    # (deployed version ahead of known-good) is false on a service with no config history.
    if "config" not in hypothesis.lower():
        fail(f"the diagnosis selected {hypothesis!r}, which does not name a config cause")

    return failures, hypothesis


def check_spans(spans: list[Any], class_belief_id: str) -> int:
    """What the durable record must and must not hold after a cold-entity incident."""
    failures = 0

    def fail(message: str) -> None:
        nonlocal failures
        failures += 1
        print(f"  FAIL {message}")

    if not spans:
        fail("no spans reached Cloud Trace inside the poll budget")
        return failures

    by_name: dict[str, list[Any]] = {}
    for span in spans:
        by_name.setdefault(span.name, []).append(span)
    print(f"--> {len(spans)} span(s): " + ", ".join(f"{n}×{len(v)}" for n, v in by_name.items()))

    incidents = by_name.get(telemetry.SPAN_INCIDENT, [])
    if len(incidents) != 1:
        fail(f"{len(incidents)} incident span(s), expected 1")
    else:
        labels = dict(incidents[0].labels)
        for attr, want in (
            (telemetry.ATTR_INCIDENT_TRIGGER_TARGET, TARGET),
            (telemetry.ATTR_INCIDENT_TRIGGER_SIGNAL, "error_rate"),
            (telemetry.ATTR_INCIDENT_DOMAIN, sre_infra.DOMAIN),
            (telemetry.ATTR_INCIDENT_ROUTED_TO, "sre-infra-agent"),
            (telemetry.ATTR_INCIDENT_OUTCOME, "ESCALATED"),
        ):
            got = attribute(labels, attr)
            if got != want:
                fail(f"{attr} is {got!r}, expected {want!r}")

    # Three chains and not four: the Verification Agent is never reached. Counting is what
    # proves it -- an absent Flash call is invisible in any single span.
    chains = by_name.get(telemetry.SPAN_REASONING_CHAIN, [])
    steps = sorted(attribute(dict(s.labels), telemetry.ATTR_REASONING_STEP) or "" for s in chains)
    print(f"--> reasoning steps: {steps}")
    if steps != ["classification", "diagnosis", "planning"]:
        fail(f"reasoning steps are {steps}, expected classification/diagnosis/planning")

    for span in chains:
        labels = dict(span.labels)
        if attribute(labels, telemetry.ATTR_REASONING_STEP) != "classification":
            continue
        recalled = attribute(labels, telemetry.ATTR_RECALL_BELIEF_IDS) or ""
        if class_belief_id not in recalled:
            fail(f"the classification span carries recall ids {recalled!r}")
        if BELIEF_ID in recalled:
            fail(f"the classification span carries {BELIEF_ID}; {TARGET} has no entity beliefs")

    decisions = by_name.get(telemetry.SPAN_AUTHORIZATION_DECISION, [])
    if len(decisions) != 1:
        fail(f"{len(decisions)} authorization span(s), expected exactly 1")
    else:
        labels = dict(decisions[0].labels)
        outcome = attribute(labels, telemetry.ATTR_DECISION_OUTCOME)
        if outcome != "APPROVE":
            fail(f"the authorization span says {outcome!r}, expected APPROVE")
        parts = [
            int(attribute(labels, attr) or -1)
            for attr in (
                telemetry.ATTR_RISK_BASE,
                telemetry.ATTR_RISK_CRITICALITY,
                telemetry.ATTR_RISK_BLAST,
                telemetry.ATTR_RISK_IRREVERSIBILITY,
            )
        ]
        total = int(attribute(labels, telemetry.ATTR_RISK_SCORE) or -1)
        print(f"--> span risk: {' + '.join(str(p) for p in parts)} = {total}")
        if tuple(parts) != EXPECTED_COMPONENTS or total != EXPECTED_SCORE or sum(parts) != total:
            fail(f"span risk arithmetic is {parts} = {total}")

    for name in (telemetry.SPAN_VERIFICATION_OUTCOME, telemetry.SPAN_BELIEF_COMMIT):
        found = by_name.get(name, [])
        if found:
            fail(f"{len(found)} {name} span(s); nothing executed, so nothing verified or learned")

    return failures


async def one_incident(
    sync_client: firestore.Client,
    async_client: Any,
    private_key: ec.EllipticCurvePrivateKey,
    class_belief_id: str,
) -> tuple[int, str, str]:
    """Inject, wake the fleet, check. Owns neither the dirty check nor the teardown."""
    telemetry.BUFFER.clear()
    tracer = trace.get_tracer("provenance.verify_incident_three")
    with tracer.start_as_current_span("provenance.verify_incident_three") as root:
        trace_id = format(root.get_span_context().trace_id, "032x")
        print(f"--> injecting the fault: {TARGET} error_rate -> {SPIKED_ERROR_RATE}")
        inject(sync_client)
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

    failures = check_result(result)
    live_failures, hypothesis = check_live_spans(class_belief_id)
    return failures + live_failures, trace_id, hypothesis


async def run(project_id: str, private_key: ec.EllipticCurvePrivateKey, runs: int) -> int:
    sync_client = firestore.Client(project=project_id)
    async_client = firestore.AsyncClient(project=project_id)

    class_belief_id = await the_class_belief(async_client)
    before = [asdict(v) for v in await beliefs.history(class_belief_id, client=async_client)]
    current = await beliefs.current(class_belief_id, client=async_client)
    print(f"==> memory holds {class_belief_id} v{current.version}: {current.statement}")
    print(f"    (confidence {current.confidence:.4f}, ADVISORY ONLY -- §6.2)")

    failures = 0
    hypotheses: list[str] = []
    trace_id = ""
    for attempt in range(1, runs + 1):
        if runs > 1:
            print(f"\n=== run {attempt}/{runs} " + "=" * 48)
        if refuse_if_dirty(sync_client):
            return failures + 1
        try:
            run_failures, trace_id, hypothesis = await one_incident(
                sync_client, async_client, private_key, class_belief_id
            )
            failures += run_failures
            hypotheses.append(hypothesis)
        finally:
            # Any exit path, Ctrl-C included. Every run restores itself, so a failure strands
            # nothing and the loop keeps going: "1 of 10 bad" and "7 of 10 bad" are different
            # findings and stopping at the first would not tell them apart.
            print(f"--> restoring: {TARGET} nominal, fault off, ledger cleared")
            failures += restore(sync_client)

    if runs > 1:
        named = sum("config" in h.lower() for h in hypotheses)
        print(f"\n--> {named}/{runs} runs named a config cause. The hypotheses selected:")
        for index, hypothesis in enumerate(hypotheses, start=1):
            print(f"    {index:2}. {hypothesis}")

    # `BatchSpanProcessor` batches, so without this the read-back races the exporter and
    # reports "nothing reached Cloud Trace" about spans still sitting in the queue.
    trace.get_tracer_provider().force_flush()  # type: ignore[attr-defined]

    # The last run only: items 9-11 already pinned the span shapes, and each read-back polls
    # up to four minutes (item 11.5's reason, a second consumer of it).
    print(f"--> reading trace {trace_id} back from Cloud Trace (indexing takes a minute or two)")
    failures += check_spans(read_back(project_id, trace_id), class_belief_id)
    print(f"    https://console.cloud.google.com/traces/list?project={project_id}&tid={trace_id}")

    after = [asdict(v) for v in await beliefs.history(class_belief_id, client=async_client)]
    if after != before:
        print(f"  FAIL {class_belief_id}'s chain changed; a class belief is read, never written")
        failures += 1
    else:
        print(f"--> {class_belief_id} unchanged: {len(before)} version(s), byte-identical")
    return failures


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--runs",
        type=int,
        default=1,
        metavar="N",
        help=(
            "how many consecutive incidents to run. This beat is thirty seconds of video and "
            "the hypothesis is the one thing a live model decides, so a flake rate is worth "
            "measuring before the demo depends on it. Each run injects and restores around "
            "itself; the Cloud Trace read-back happens on the last one only."
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

    failures = asyncio.run(run(project_id, load_private_key(pem), args.runs))
    if failures:
        print(f"\nFAILED: {failures} check(s).")
        return 1
    print(
        "\nOK: item 24's verify line holds. A class belief was nominated for a service with "
        "no memory of its own, the fleet diagnosed a config cause on it, and the executor "
        "refused an action the entity cannot receive."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
