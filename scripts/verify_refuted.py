#!/usr/bin/env python3
"""Items 19 and 20's `verify:` lines, live: a refuted remediation teaches, is retried exactly
once, and then escalates; an unverified one teaches nothing.

    PROVENANCE_PLANNER_KEY="$(cat ~/planner.pem)" GOOGLE_CLOUD_PROJECT=provenance-hackathon \\
      GOOGLE_GENAI_USE_VERTEXAI=1 GOOGLE_CLOUD_LOCATION=global \\
      .venv/bin/python scripts/verify_refuted.py

`ARCHITECTURE.md` §10's Verification row is two clauses and this script is both, in order:

  * **REFUTED, twice.** `error_rate_spike` + `rollback_fails`. The fleet diagnoses, proposes,
    is authorized and executes -- and the rollback deploys v41 while leaving the rate at 0.38,
    so the Verification Agent's honest answer to its own pre-declared predicate is `REFUTED`.
    §7.2's second row then applies: a belief committed at 0.60 with status
    `ROLLBACK_INEFFECTIVE`. §7.1's second budget applies next (item 20): the Planner is
    re-planned **once**, with the refutation as input, and the switch is a switch rather than a
    coin, so the second attempt is refuted too -- a `v2` re-affirmation citing both
    observations, an incident still `ESCALATED`, and **no third attempt anywhere in the
    trace**. That last clause is checked by counting, not by asserting: two verification spans
    carrying `attempt` 1 and 2, two authorization spans, two planning chains, and nothing at 3.
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

The `v2` is the half the offline suite structurally cannot hold, which is why it is asserted
here. §2.2's novelty check compares `(source_id, observed_at)` pairs and `beliefs.TIMESTAMP` has
second resolution; a `FakeLlm` finishes both attempts inside one second, so offline the second
commit is correctly refused `NO_NEW_EVIDENCE`. Live, a model call separates them. Delete item
20's per-attempt `observed_at` stamp and the whole offline suite stays green -- this script is
the only thing that goes red.

Costs four `gemini-2.5-pro` calls plus two `gemini-3.5-flash` for the REFUTED half (the retry is
one more of each), and three Pro calls for the INCONCLUSIVE one -- the Verification Agent is
never invoked there, which is the point. Needs credentials, so it is not in CI; `tests/test_incident.py` is the offline half.
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
    """§7.2's second row and §7.1's second budget: the negative belief, retried once, then open.

    The belief reported here is the **retry's** -- `IncidentResult` carries the last attempt.
    It is a `v2` and not a `v1`: same status and same `verified_system_observation` class, so
    it is a re-affirmation facing the 0.50 door rather than a flip facing 0.70, and it cites
    both observations. The confidence does not move, and that is §4.3 collapsing a source class
    to its least-decayed item rather than memory failing to pay (item 18's lesson).
    """
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
    # Item 20's line, on the returned object; `check_spans` is where the trace says the same.
    if result.refuted_attempts != 2:
        failures += fail(
            f"{result.refuted_attempts} refutation(s), expected 2 -- one attempt and one retry"
        )

    if result.belief is None:
        failures += fail("REFUTED wrote no belief; §7.2 says confirmed refutation is knowledge")
    else:
        if (result.belief.outcome, result.belief.reason) != ("COMMIT", "ABOVE_THRESHOLD"):
            failures += fail(f"belief was {result.belief.outcome}/{result.belief.reason}")
        if result.belief.version != 2:
            failures += fail(
                f"belief is v{result.belief.version}, expected v2 -- the retry re-affirms what "
                "the first attempt committed. A v1 here means both attempts stamped the same "
                "`observed_at` and §2.2 refused the second NO_NEW_EVIDENCE (item 20)."
            )
        if abs(result.belief.confidence - EXPECTED_CONFIDENCE) > 1e-6:
            failures += fail(
                f"confidence {result.belief.confidence:.4f}, expected {EXPECTED_CONFIDENCE}"
            )
        try:
            policy.verify_commit(result.belief, policy.public_key_pem())
        except policy.CommitInvalid as error:
            failures += fail(f"the commit does not verify: {error}")

    # What the store actually holds, read before the teardown deletes it. `result.belief` is
    # what the engine decided; this is the chain a later incident would recall.
    versions = client.collection(f"{beliefs.COLLECTION}/{BELIEF_ID}/versions")
    stored = versions.document("1").get().to_dict() or {}
    retry = versions.document("2").get().to_dict() or {}
    for number, document in (("1", stored), ("2", retry)):
        if document.get("status") != incident.REFUTED_STATUS:
            failures += fail(
                f"v{number}'s stored status is {document.get('status')!r}, "
                f"expected {incident.REFUTED_STATUS!r}"
            )
        elif document.get("status") == incident.BELIEF_STATUS:
            failures += fail(f"v{number} carries the status a confirmed run writes")
    if retry.get("supersedes") != 1:
        failures += fail(f"v2 supersedes {retry.get('supersedes')!r}, expected 1")
    # A superseding version cites the accumulated set (item 13), so the retry's own observation
    # is the second entry rather than the only one. Two attempts, two readings of the service.
    if len(set(retry.get("evidence", []))) != 2:
        failures += fail(
            f"v2 cites {retry.get('evidence')}; expected the two attempts' observations. One id "
            "means the retry re-cited the first attempt's reading rather than making its own."
        )

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
            f"2 attempts, belief v2 {incident.REFUTED_STATUS} at {EXPECTED_CONFIDENCE} "
            "superseding v1"
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


def check_attempts(by_name: dict[str, list[dict[str, str]]], verified: list[dict[str, str]]) -> int:
    """Item 20's line: "no third attempt occurs anywhere in the trace", proven by counting.

    Four independent counts, because one of them alone is weak evidence. Two verifications says
    the loop judged twice; two authorizations says it really went back through the gateway
    rather than re-verifying one execution; two planning chains says the Planner was asked
    twice and no more; and the `attempt` values say the trace itself numbers them 1 and 2.
    """
    failures = 0
    numbered = sorted(
        int(labels.get(telemetry.ATTR_VERIFICATION_ATTEMPT, 0)) for labels in verified
    )
    if numbered != [1, 2]:
        failures += fail(f"verification attempts are {numbered}, expected [1, 2]")
    authorized = by_name.get(telemetry.SPAN_AUTHORIZATION_DECISION, [])
    if len(authorized) != 2:
        failures += fail(f"{len(authorized)} authorization span(s), expected 2")
    planning = [
        labels
        for labels in by_name.get(telemetry.SPAN_REASONING_CHAIN, [])
        if attribute(labels, telemetry.ATTR_REASONING_STEP) == "planning"
    ]
    if len(planning) != 2:
        failures += fail(
            f"{len(planning)} planning reasoning chain(s), expected 2 -- "
            "a third means the Planner was asked again after the budget was spent"
        )
    if not failures:
        print("    ok  bounded        2 attempts numbered 1 and 2, and nothing at 3")
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

    # One verification on the INCONCLUSIVE half; two on the REFUTED one, because item 20
    # re-plans the first refutation and the switch fails the retry the same way.
    expected_verifications = 2 if expect_belief else 1
    if len(incidents) != 1:
        return fail(f"{len(incidents)} incident span(s) on the trace, expected 1")
    if len(verified) != expected_verifications:
        return fail(f"{len(verified)} verification span(s), expected {expected_verifications}")
    if expect_belief:
        failures += check_attempts(by_name, verified)

    # The incident span carries the *last* attempt's predicate: it is set from
    # `scratch.validated` when the root span closes, and the retry replaces it. So the pairing
    # asserted live is the final attempt's; each attempt's own is held offline by
    # `test_the_verification_span_carries_the_predicate_declared_before_execution`.
    last = max(verified, key=lambda labels: int(labels.get(telemetry.ATTR_VERIFICATION_ATTEMPT, 1)))
    declared = attribute(incidents[0], telemetry.ATTR_INCIDENT_PREDICATE_ID)
    checked = attribute(last, telemetry.ATTR_VERIFICATION_PREDICATE_ID)
    if not declared or declared != checked:
        failures += fail(f"predicate {checked!r} was verified, {declared!r} was declared")

    expected_outcome = "REFUTED" if expect_belief else "INCONCLUSIVE"
    for labels in verified:
        outcome = attribute(labels, telemetry.ATTR_VERIFICATION_OUTCOME)
        if outcome != expected_outcome:
            failures += fail(f"a verification span says {outcome}, expected {expected_outcome}")
        flag = attribute(labels, telemetry.ATTR_VERIFICATION_BELIEF_WRITTEN)
        if str(flag).lower() != str(expect_belief).lower():
            failures += fail(f"belief_written is {flag}, expected {expect_belief}")
    written = attribute(last, telemetry.ATTR_VERIFICATION_BELIEF_WRITTEN)

    # One commit per verification that learned something, so two on the retried half and none
    # at all on the ambiguous one -- §7.2's third row is an absence.
    expected_commits = expected_verifications if expect_belief else 0
    if len(committed) != expected_commits:
        failures += fail(f"{len(committed)} belief.commit span(s), expected {expected_commits}")
    elif expect_belief:
        for labels in committed:
            # The belief span borrows `provenance.decision.*` for its outcome, reason and
            # signature -- item 2 gave the two pipelines one vocabulary rather than two.
            if attribute(labels, telemetry.ATTR_DECISION_OUTCOME) != "COMMIT":
                failures += fail(
                    f"a belief span says {attribute(labels, telemetry.ATTR_DECISION_OUTCOME)}/"
                    f"{attribute(labels, telemetry.ATTR_DECISION_REASON)}"
                )
            if attribute(labels, telemetry.ATTR_BELIEF_STATUS) != incident.REFUTED_STATUS:
                failures += fail(
                    f"a belief span's status is "
                    f"{attribute(labels, telemetry.ATTR_BELIEF_STATUS)}, "
                    f"expected {incident.REFUTED_STATUS}"
                )
            if not attribute(labels, telemetry.ATTR_DECISION_SIGNATURE):
                failures += fail("a belief.commit span carries no signature")
        # Which commit is which, by what it says rather than by where it sits: Cloud Trace
        # returns spans in no promised order, and item 20's whole belief story is that one of
        # these two opened the chain and the other re-affirmed it. A first belief supersedes
        # nothing; the retry's names its predecessor rather than opening a second chain.
        chain = {attribute(labels, telemetry.ATTR_BELIEF_SUPERSEDES) for labels in committed}
        if chain != {None, "1"}:
            failures += fail(f"the belief spans supersede {chain}, expected one v1 and one v2")

    if not failures:
        print(
            f"    ok  trace          {expected_outcome} x{len(verified)} on predicate "
            f"{declared}, declared before execution; belief_written={written}"
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
            # The retry's hazard, and the mirror of the one above. The retry prompt hands the
            # Planner the rate its last attempt left behind, and a threshold at or above that
            # value is satisfied by the failure itself -- so the refutation verifies as a
            # success. Observed live before `incident.py` gave the retry predicate a ceiling.
            # Assert-only and in the script for item 11.5's reason: a regex over natural
            # language on the production path would spend a retry budget on something that is
            # not a schema failure.
            elif switch == "rollback_fails" and max(thresholds(predicate)) >= SPIKED_ERROR_RATE:
                print(
                    f"    WARN  the predicate's threshold is at or above {SPIKED_ERROR_RATE}, "
                    "the rate the failed rollback\n          left behind, so it is satisfied by "
                    "the failure. Any CONFIRMED below is that, not a\n          working "
                    "remediation — re-run rather than reading it as a defect."
                )
        print(f"    verification {result.verification}   belief {result.belief}")

        expect_belief = switch == "rollback_fails"
        checker = check_refuted if expect_belief else check_inconclusive
        failures = checker(result, sync_client)
        # Read before the teardown removes it: the ledger records the authorized action either
        # way, because the action *was* authorized -- what differs is what came of it. The
        # retried half records two, and that is correct rather than a duplicate: item 20 goes
        # back through the gateway for the second attempt, so two actions really were
        # authorized and §6.4 has to be able to flag either.
        expected_records = 2 if expect_belief else 1
        records = authorizations_for_target(sync_client)
        if len(records) != expected_records:
            failures += fail(
                f"{len(records)} authorization ledger record(s), expected {expected_records}"
            )
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
