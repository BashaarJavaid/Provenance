#!/usr/bin/env python3
"""Item 19's `verify:` line, live: a refuted remediation teaches, an unverified one does not.

    PROVENANCE_PLANNER_KEY="$(cat ~/planner.pem)" GOOGLE_CLOUD_PROJECT=provenance-hackathon \\
      GOOGLE_GENAI_USE_VERTEXAI=1 GOOGLE_CLOUD_LOCATION=global \\
      .venv/bin/python scripts/verify_refuted.py

`ARCHITECTURE.md` §10's Verification row is two clauses and this script is both, in order:

  * **REFUTED.** `error_rate_spike` + `rollback_fails`. The fleet diagnoses, proposes, is
    authorized and executes -- and the rollback deploys v41 while leaving the rate at 0.38, so
    the Verification Agent's honest answer to its own pre-declared predicate is `REFUTED`.
    §7.2's second row then applies: one belief committed at 0.60 with status
    `ROLLBACK_INEFFECTIVE`, and an incident that is still `ESCALATED`.
  * **INCONCLUSIVE.** `error_rate_spike` + `verification_ambiguous`. The rollback *works* --
    v41, rate back to nominal -- and then nothing verifies it. §7.3 says an action that
    executed and was never checked is `INCONCLUSIVE`, and §7.2's third row says that writes
    **nothing at all**. The assertion is a `beliefs/` document that does not exist.

The two halves together are what make either one evidence. A run that wrote no belief would
pass the second clause on a fleet whose memory was simply broken; a run that wrote one would
pass the first on a fleet that commits on anything. Asserting both, in one process, against
the same entity, is the only version of this that can fail for the right reason.

`--refuted` / `--inconclusive` run one half; the default runs both.

**Writes live state**, and takes item 8's posture about it: `refuse_if_dirty()` before
anything, and one `try/finally` per half restoring the service fixture, all three switches,
the belief chain and the ledger record on any exit path including Ctrl-C.

**It imports its teardown from `verify_incident_one.py` rather than copying it**, which is a
deliberate break from the one-script-one-file convention every other script here follows.
These two scripts are the only things that write these particular live documents, and two
restore paths over one fixture is a pair that drifts -- the first time one of them learns
about a new field and the other does not, a run silently leaves state behind. `scripts/` is on
`sys.path` when a script is run directly and that module's `main()` is `__main__`-guarded, so
the import costs a few constants and nothing else.

Costs three `gemini-2.5-pro` calls plus one `gemini-3.5-flash` for the REFUTED half, and three
Pro calls for the INCONCLUSIVE one -- the Verification Agent is never invoked there, which is
the point. Needs credentials, so it is not in CI; `tests/test_incident.py` is the offline half.
"""

from __future__ import annotations

import argparse
import asyncio
import os
import sys
from typing import Any

from cryptography.hazmat.primitives.asymmetric import ec
from google.cloud import firestore
from opentelemetry import trace
from verify_incident_one import (
    BELIEF_ID,
    OBSERVED_AT,
    SPIKED_ERROR_RATE,
    TARGET,
    attribute,
    authorizations_for_target,
    load_private_key,
    read_back,
    refuse_if_dirty,
    restore,
    thresholds,
)

from provenance import action, beliefs, incident, policy, telemetry
from provenance.synthetic import company

# §4.3 over one fresh `verified_system_observation`: `1 - (1 - 0.60) = 0.60`. The same number
# incident #1 commits, because it is the same single class of evidence -- what differs between
# a confirmed run and a refuted one is the *status*, never the arithmetic.
EXPECTED_CONFIDENCE = 0.60


def inject(client: firestore.Client, switch: str) -> None:
    """The spike plus exactly one of §9's other two switches, as `inject_fault.py` writes them.

    Written explicitly rather than left at whatever the last run set: two of these on at once
    is a state neither half of this script means, and `rollback_fails` would make the
    INCONCLUSIVE half's "the rollback worked" clause quietly false.
    """
    client.collection("services").document(TARGET).update(
        {"error_rate": SPIKED_ERROR_RATE, "healthy": False}
    )
    client.collection("fault_injection").document(TARGET).update(
        {
            "error_rate_spike": True,
            "rollback_fails": switch == "rollback_fails",
            "verification_ambiguous": switch == "verification_ambiguous",
        }
    )


def fail(message: str) -> int:
    print(f"FAIL: {message}", file=sys.stderr)
    return 1


def check_reached_verification(result: Any) -> int:
    """Everything both halves share: one typed rollback, authorized, and actually executed.

    If any of this is false the outcome under test was never reached, and reporting on the
    verification would be reporting on an incident that stopped somewhere else.
    """
    failures = 0
    if result.action is None:
        return fail("no action was ever validated; the incident stopped before the gateway")
    if (result.action.action_class, result.action.target) != ("ROLLBACK_CONFIG", TARGET):
        failures += fail(f"expected ROLLBACK_CONFIG({TARGET}), got {result.action}")
    if result.decision is None or result.decision.outcome != "APPROVE":
        failures += fail(f"expected an APPROVE, got {result.decision}")
    if result.execution is None:
        failures += fail("nothing executed, so there was nothing to verify")
    elif (result.execution.from_version, result.execution.to_version) != ("v42", "v41"):
        failures += fail(f"expected v42 -> v41, got {result.execution}")
    if result.malformed_attempts:
        failures += fail(f"{result.malformed_attempts} malformed emission(s)")
    if not failures:
        print("    ok  reached        one typed ROLLBACK_CONFIG, approved, executed v42 -> v41")
    return failures


def check_refuted(result: Any, client: firestore.Client) -> int:
    """§7.2's second row: the negative belief, and an incident that is still open."""
    failures = check_reached_verification(result)

    if result.execution is not None and not result.execution.rollback_failed:
        failures += fail("the rollback_fails switch did not reach the executor")
    if result.verification != "REFUTED":
        failures += fail(
            f"verification returned {result.verification}, expected REFUTED. "
            "Check the predicate below -- item 11.5's hazard has a sharper form here."
        )
    if result.outcome != "ESCALATED":
        failures += fail(f"incident ended {result.outcome}, expected ESCALATED")

    if result.belief is None:
        failures += fail("REFUTED wrote no belief; §7.2 says confirmed refutation is knowledge")
    else:
        if (result.belief.outcome, result.belief.reason) != ("COMMIT", "ABOVE_THRESHOLD"):
            failures += fail(f"belief was {result.belief.outcome}/{result.belief.reason}")
        if result.belief.version != 1:
            failures += fail(f"belief is v{result.belief.version}, expected v1 on a cold chain")
        if abs(result.belief.confidence - EXPECTED_CONFIDENCE) > 1e-6:
            failures += fail(
                f"confidence {result.belief.confidence:.4f}, expected {EXPECTED_CONFIDENCE}"
            )
        try:
            policy.verify_commit(result.belief, policy.public_key_pem())
        except policy.CommitInvalid as error:
            failures += fail(f"the commit does not verify: {error}")

    # What the store actually holds, read before the teardown deletes it. `result.belief` is
    # what the engine decided; this is the version a later incident would recall.
    stored = (
        client.collection(f"{beliefs.COLLECTION}/{BELIEF_ID}/versions")
        .document("1")
        .get()
        .to_dict()
        or {}
    )
    if stored.get("status") != incident.REFUTED_STATUS:
        failures += fail(
            f"stored status is {stored.get('status')!r}, expected {incident.REFUTED_STATUS!r}"
        )
    elif stored.get("status") == incident.BELIEF_STATUS:
        failures += fail("the refuted run wrote the status a confirmed one writes")

    # The failed rollback still deployed. A rollback that skipped its own write would make the
    # refutation a fact about the executor rather than about the remediation (ADR-014).
    state = client.collection("services").document(TARGET).get().to_dict() or {}
    if state.get("current_config_version") != "v41":
        failures += fail(f"{TARGET} is on {state.get('current_config_version')}, expected v41")
    if state.get("error_rate") != SPIKED_ERROR_RATE:
        failures += fail(
            f"{TARGET} error_rate is {state.get('error_rate')}, "
            f"expected the deviation to survive at {SPIKED_ERROR_RATE}"
        )
    if not failures:
        print(
            f"    ok  refuted        v41 deployed, rate still {SPIKED_ERROR_RATE}, "
            f"belief v1 {incident.REFUTED_STATUS} at {EXPECTED_CONFIDENCE}"
        )
    return failures


def check_inconclusive(result: Any, client: firestore.Client) -> int:
    """§7.2's third row: nothing. The assertion is a document that is not there."""
    failures = check_reached_verification(result)

    if result.execution is not None and result.execution.rollback_failed:
        failures += fail("the rollback failed; this half needs one that worked")
    if result.verification != "INCONCLUSIVE":
        failures += fail(f"verification returned {result.verification}, expected INCONCLUSIVE")
    if result.outcome != "ESCALATED":
        failures += fail(f"incident ended {result.outcome}, expected ESCALATED")
    if result.belief is not None:
        failures += fail(f"ambiguity wrote a belief: {result.belief}. §7.2: no partial credit")

    if client.collection(beliefs.COLLECTION).document(BELIEF_ID).get().exists:
        failures += fail(
            f"{beliefs.COLLECTION}/{BELIEF_ID} exists; nothing should have been written"
        )

    # The control is that the remediation *worked*. Without it, "no belief" is equally
    # explained by an incident that never got far enough to write one.
    nominal = company.service(TARGET).error_rate
    state = client.collection("services").document(TARGET).get().to_dict() or {}
    if state.get("current_config_version") != "v41":
        failures += fail(f"{TARGET} is on {state.get('current_config_version')}, expected v41")
    if state.get("error_rate") != nominal:
        failures += fail(f"{TARGET} error_rate is {state.get('error_rate')}, expected {nominal}")
    if not failures:
        print(
            f"    ok  inconclusive   the rollback worked (v41, {nominal}) and nothing verified "
            f"it, so nothing was learned"
        )
    return failures


def check_spans(spans: list[Any], expect_belief: bool) -> int:
    """The trace half. `predicate_id` is the pairing that makes "pre-declared" checkable."""
    failures = 0
    by_name: dict[str, list[dict[str, str]]] = {}
    for span in spans:
        by_name.setdefault(span.name, []).append(dict(span.labels))

    incidents = by_name.get(telemetry.SPAN_INCIDENT, [])
    verified = by_name.get(telemetry.SPAN_VERIFICATION_OUTCOME, [])
    committed = by_name.get(telemetry.SPAN_BELIEF_COMMIT, [])

    if len(incidents) != 1:
        return fail(f"{len(incidents)} incident span(s) on the trace, expected 1")
    if len(verified) != 1:
        return fail(f"{len(verified)} verification span(s), expected 1")

    declared = attribute(incidents[0], telemetry.ATTR_INCIDENT_PREDICATE_ID)
    checked = attribute(verified[0], telemetry.ATTR_VERIFICATION_PREDICATE_ID)
    if not declared or declared != checked:
        failures += fail(f"predicate {checked!r} was verified, {declared!r} was declared")

    expected_outcome = "REFUTED" if expect_belief else "INCONCLUSIVE"
    if attribute(verified[0], telemetry.ATTR_VERIFICATION_OUTCOME) != expected_outcome:
        failures += fail(
            f"the verification span says "
            f"{attribute(verified[0], telemetry.ATTR_VERIFICATION_OUTCOME)}, "
            f"expected {expected_outcome}"
        )
    written = attribute(verified[0], telemetry.ATTR_VERIFICATION_BELIEF_WRITTEN)
    if str(written).lower() != str(expect_belief).lower():
        failures += fail(f"belief_written is {written}, expected {expect_belief}")

    if len(committed) != int(expect_belief):
        failures += fail(f"{len(committed)} belief.commit span(s), expected {int(expect_belief)}")
    elif expect_belief:
        labels = committed[0]
        # The belief span borrows `provenance.decision.*` for its outcome, reason and
        # signature -- item 2 gave the two pipelines one vocabulary rather than two.
        if attribute(labels, telemetry.ATTR_DECISION_OUTCOME) != "COMMIT":
            failures += fail(
                f"the belief span says {attribute(labels, telemetry.ATTR_DECISION_OUTCOME)}/"
                f"{attribute(labels, telemetry.ATTR_DECISION_REASON)}"
            )
        if attribute(labels, telemetry.ATTR_BELIEF_STATUS) != incident.REFUTED_STATUS:
            failures += fail(
                f"the belief span's status is "
                f"{attribute(labels, telemetry.ATTR_BELIEF_STATUS)}, "
                f"expected {incident.REFUTED_STATUS}"
            )
        if attribute(labels, telemetry.ATTR_BELIEF_SUPERSEDES) is not None:
            failures += fail("a first belief supersedes nothing")
        if not attribute(labels, telemetry.ATTR_DECISION_SIGNATURE):
            failures += fail("the belief.commit span carries no signature")

    if not failures:
        print(
            f"    ok  trace          {expected_outcome} on predicate {declared}, declared "
            f"before execution; belief_written={written}"
        )
    return failures


async def one_half(
    project_id: str,
    private_key: ec.EllipticCurvePrivateKey,
    *,
    switch: str,
    title: str,
) -> int:
    """One injected incident, checked in the store and then in Cloud Trace. Restores itself."""
    sync_client = firestore.Client(project=project_id)
    async_client = firestore.AsyncClient(project=project_id)

    print(f"\n=== {title} " + "=" * max(0, 56 - len(title)))
    if refuse_if_dirty(sync_client):
        return 1

    tracer = trace.get_tracer("provenance.verify_refuted")
    try:
        with tracer.start_as_current_span("provenance.verify_refuted") as root:
            trace_id = format(root.get_span_context().trace_id, "032x")
            print(f"--> injecting: error_rate -> {SPIKED_ERROR_RATE}, {switch} on")
            inject(sync_client, switch)
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
        print(f"    incident {result.incident_id} -> {result.outcome}")
        if result.action is not None:
            predicate = result.action.success_predicate
            print(f"    predicate {action.predicate_id(result.action)}  {predicate}")
            # Item 11.5's hazard, in its sharper form: a failed rollback still deploys v41, so
            # a predicate naming *only* the version is honestly CONFIRMED here and this run
            # would fail for a reason that is not a defect. Say so rather than let a confusing
            # CONFIRMED stand on its own. Assert-only, and only in the script.
            if switch == "rollback_fails" and not thresholds(predicate):
                print(
                    "    WARN  the predicate names no error-rate threshold. A failed rollback "
                    "still deploys v41,\n          so a version-only predicate is honestly "
                    "CONFIRMED — re-run rather than reading this as a defect."
                )
        print(f"    verification {result.verification}   belief {result.belief}")

        expect_belief = switch == "rollback_fails"
        checker = check_refuted if expect_belief else check_inconclusive
        failures = checker(result, sync_client)
        # Read before the teardown removes it: the ledger records the authorized action either
        # way, because the action *was* authorized -- what differs is what came of it.
        if len(authorizations_for_target(sync_client)) != 1:
            failures += fail("expected exactly one authorization ledger record")
    finally:
        print("--> restoring: v42, nominal error rate, all switches off, belief and ledger gone")
        restore(sync_client)

    provider = trace.get_tracer_provider()
    provider.force_flush()  # type: ignore[attr-defined]
    print(f"--> reading trace {trace_id} back from Cloud Trace (indexing takes a minute or two)")
    url = f"https://console.cloud.google.com/traces/list?project={project_id}&tid={trace_id}"
    spans = read_back(project_id, trace_id)
    if not spans:
        print(f"FAIL: the incident's spans never reached Cloud Trace\n{url}", file=sys.stderr)
        return failures + 1
    failures += check_spans(spans, expect_belief)
    print(f"    {url}")
    return failures


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--refuted", action="store_true", help="run only the failed-rollback half")
    parser.add_argument(
        "--inconclusive", action="store_true", help="run only the forced-ambiguity half"
    )
    args = parser.parse_args()

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
    halves = [
        ("rollback_fails", "REFUTED: the remediation ran and did not work"),
        ("verification_ambiguous", "INCONCLUSIVE: it worked and nobody could confirm it"),
    ]
    if args.refuted != args.inconclusive:
        halves = [halves[0]] if args.refuted else [halves[1]]

    # Both halves run even if the first fails. "the negative belief did not commit" and "both
    # rows are broken" are different findings, and each half restores itself.
    failures = sum(
        asyncio.run(one_half(project_id, private_key, switch=switch, title=title))
        for switch, title in halves
    )
    if failures:
        print(f"\n{failures} check(s) failed.", file=sys.stderr)
        return 1
    print(
        "\n--> three-valued verification, exercised rather than designed: a refuted remediation"
        "\n    committed what it disproved, and an unverifiable one committed nothing at all"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
