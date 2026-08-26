"""Item 32 — the `--memory-disabled` A/B counterfactual on incident #2.

Three ADRs and two ROADMAP notes defer a causation claim to this script. Items 18 and 24 each
recorded that they could not honestly say memory *caused* a better diagnosis, and each named
this measurement as where the number would come from. So this is the number, and the report
it feeds (`docs/counterfactual-report.md`) is equally careful about what it still does not
license: `sre_infra.py` carries its own config-regression hint in both arms, so a difference
here is a difference in what the run *cost*, never proof of what it concluded.

The item asks for four metrics. Two of them are not what its wording assumed:

  * **wall-clock** — measured here, around `run_incident()` alone. Not read off the spans: a
    Cloud Trace read-back lags by up to two minutes, and the honest number is the one a person
    waited through, recall included.
  * **tool calls** — *there are none*. No agent in this fleet is built with `tools=`; all six
    are output-schema-constrained `LlmAgent`s, and `provenance/tools.py` is a declarative
    action-class table (`ADR-011`), not an ADK tool registry. What is counted instead is
    **model calls** — requests, via item 32's `provenance.reasoning.model_calls`.
  * **tokens** — off the reasoning spans, where they have lived since item 9.
  * **hypotheses evaluated before the correct one** — not stored anywhere, and not derivable:
    nothing records an ordering. What exists is `hypotheses_considered`, an integer the model
    asserts about itself. It is reported as exactly that. It is telemetry and never authority
    (§1.1 property 3 is untouched: no deterministic decision reads it), but a reader must know
    the number is a claim rather than an observation.

Two modes:

    scripts/verify_counterfactual.py --record     # live; credentials; writes the artifacts
    scripts/verify_counterfactual.py              # offline; re-derives the table from them

The second is the `verify:` line — "the A/B table is reproducible from the committed run
artifacts" — and it needs no credentials, no network and no cloud project, which is why
`tests/test_counterfactual.py` can call it and CI can catch a report edited away from its
own evidence.

Each recorded trial is a *pair* of incidents, because incident #2's premise is that a belief
is already in the store:

    refuse_if_dirty -> incident #1 cold (writes v1) -> restore_service()
                    -> MEASURED incident #2 with memory=<arm> -> restore()

Only the second is measured. The arms are interleaved on/off/on/off rather than run in
blocks, so that drift in Vertex latency over the session lands on both arms instead of one.

The two arms differ in exactly one thing: whether `run_incident()` calls `recall.recall()`.
The belief is present either way and the §2.2 commit runs either way -- both arms end at v2.
Disabling the commit as well would have been a second variable, and the table could then not
attribute its own delta to recall.

Needs the same environment as `scripts/verify_incident_one.py`: `GOOGLE_CLOUD_PROJECT`,
`PROVENANCE_PLANNER_KEY`, `GOOGLE_GENAI_USE_VERTEXAI=1`, `GOOGLE_CLOUD_LOCATION=global`.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import statistics
import sys
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.asymmetric import ec
from google.cloud import firestore
from verify_incident_one import (
    _one_incident,
    attribute,
    load_private_key,
    read_back,
    refuse_if_dirty,
    restore,
    restore_service,
)

from provenance import incident, telemetry

REPO = Path(__file__).resolve().parent.parent
ARTIFACTS = REPO / "docs" / "counterfactual"
# The served table lives under `provenance/` and not beside its raw runs because the
# Dockerfile copies `pyproject.toml` and `provenance/` and nothing else -- a route reading
# `docs/` would 404 in the deployed image while working perfectly on a laptop.
TABLE = REPO / "provenance" / "web" / "counterfactual.json"
REPORT = REPO / "docs" / "counterfactual-report.md"

# The report carries the table between these, and this script regenerates and compares it.
# CLAUDE.md's rule is that a measured number has one home; a hand-typed second copy in the
# prose is exactly how the docs come to disagree with themselves.
TABLE_START = "<!-- table:start -->"
TABLE_END = "<!-- table:end -->"

ARM_ON = "memory-on"
ARM_OFF = "memory-off"
ARMS = (ARM_ON, ARM_OFF)

DIAGNOSIS_STEP = "diagnosis"

# (key in a run artifact, label in the table, unit). Order is the table's order.
METRICS: tuple[tuple[str, str, str], ...] = (
    ("wall_clock_s", "wall-clock", "s"),
    ("model_calls", "model calls", ""),
    ("input_tokens", "input tokens", ""),
    ("output_tokens", "output tokens", ""),
    ("hypotheses_considered", "hypotheses considered", "model-asserted"),
)


# --- the live half --------------------------------------------------------------------------


def measure(spans: list[Any]) -> dict[str, Any]:
    """The three span-borne metrics, summed over one incident's reasoning chains.

    Summed over *every* step, not only the domain agent's: what the arm costs is what the
    whole loop spent, and §7.1's re-plan is a cost memory could plausibly move. The hypothesis
    count is the exception -- it belongs to the one step that formed hypotheses, and summing
    it across the Orchestrator's classification and the verifier's read-back would produce a
    number about nothing.
    """
    chains = [s for s in spans if s.name == telemetry.SPAN_REASONING_CHAIN]

    def total(attr: str) -> int:
        return sum(int(attribute(dict(s.labels), attr) or 0) for s in chains)

    diagnosis = [
        s
        for s in chains
        if attribute(dict(s.labels), telemetry.ATTR_REASONING_STEP) == DIAGNOSIS_STEP
    ]
    hypotheses = 0
    selected = ""
    if diagnosis:
        labels = dict(diagnosis[0].labels)
        hypotheses = int(attribute(labels, telemetry.ATTR_REASONING_HYPOTHESES_CONSIDERED) or 0)
        selected = attribute(labels, telemetry.ATTR_REASONING_SELECTED_HYPOTHESIS) or ""

    return {
        "model_calls": total(telemetry.ATTR_REASONING_MODEL_CALLS),
        "input_tokens": total(telemetry.ATTR_REASONING_INPUT_TOKENS),
        "output_tokens": total(telemetry.ATTR_REASONING_OUTPUT_TOKENS),
        "hypotheses_considered": hypotheses,
        "selected_hypothesis": selected,
        "reasoning_spans": len(chains),
    }


async def one_trial(
    project_id: str,
    private_key: ec.EllipticCurvePrivateKey,
    *,
    run: int,
    arm: str,
) -> tuple[int, dict[str, Any] | None]:
    """One cold seeding incident, then one measured incident under `arm`. Returns failures."""
    sync_client = firestore.Client(project=project_id)
    async_client = firestore.AsyncClient(project=project_id)

    if refuse_if_dirty(sync_client):
        return 1, None

    failures = 0
    try:
        print(f"\n=== run {run} · {arm} · seeding incident #1 (cold) " + "=" * 22)
        cold, _, _, _ = await _one_incident(sync_client, async_client, private_key)
        failures += cold

        print("\n--> re-injecting the same deviation, leaving memory in place")
        restore_service(sync_client)

        print(f"\n=== run {run} · {arm} · MEASURED incident #2 " + "=" * 27)
        measured, trace_id, result, elapsed = await _one_incident(
            sync_client,
            async_client,
            private_key,
            expect_version=2,
            memory=arm == ARM_ON,
        )
        failures += measured
    finally:
        # Every exit path, including a Ctrl-C mid-incident. Both incidents' state goes back.
        print("\n--> restoring: v42, nominal error rate, fault off, belief and ledger deleted")
        restore(sync_client)

    print(f"\n--> reading trace {trace_id} back for the span-borne metrics")
    spans = read_back(project_id, trace_id)
    if not spans:
        print("FAIL: the measured incident's spans never reached Cloud Trace", file=sys.stderr)
        return failures + 1, None

    record: dict[str, Any] = {
        "run": run,
        "arm": arm,
        "incident_id": result.incident_id,
        "trace_id": trace_id,
        "outcome": result.outcome,
        "belief_version": result.belief.version if result.belief else None,
        "wall_clock_s": round(elapsed, 1),
        **measure(spans),
    }
    print(
        f"    measured  {elapsed:.1f}s · {record['model_calls']} model calls · "
        f"{record['input_tokens']}+{record['output_tokens']} tokens · "
        f"{record['hypotheses_considered']} hypotheses ({record['selected_hypothesis']})"
    )
    return failures, record


async def record(project_id: str, private_key: ec.EllipticCurvePrivateKey, runs: int) -> int:
    """`runs` trials per arm, interleaved, each one written out as it completes.

    Written as it completes rather than at the end: twelve live incidents is a long session,
    and a crash on the eleventh should not throw away the ten that already ran.
    """
    ARTIFACTS.mkdir(parents=True, exist_ok=True)
    failures = 0
    for run in range(1, runs + 1):
        for arm in ARMS:
            trial_failures, artifact = await one_trial(project_id, private_key, run=run, arm=arm)
            failures += trial_failures
            if artifact is None:
                print(f"FAIL: run {run} {arm} produced no artifact", file=sys.stderr)
                continue
            path = ARTIFACTS / f"run-{run}-{arm}.json"
            path.write_text(json.dumps(artifact, indent=2) + "\n")
            print(f"    wrote     {path.relative_to(REPO)}")

    if failures:
        print(f"\n{failures} failure(s) across the recorded runs.", file=sys.stderr)
        return 1

    built = build_table(load_runs())
    TABLE.write_text(json.dumps(built, indent=2) + "\n")
    print(f"\n--> wrote {TABLE.relative_to(REPO)} — {built['runs_per_arm']} runs per arm")
    print(render(built))
    print("Paste the block above between the report's table markers, then re-run without")
    print("--record to check the three copies agree.")
    return 0


# --- the offline half: the `verify:` line ---------------------------------------------------


def load_runs() -> list[dict[str, Any]]:
    return [json.loads(path.read_text()) for path in sorted(ARTIFACTS.glob("run-*.json"))]


def build_table(runs: list[dict[str, Any]]) -> dict[str, Any]:
    """The medians, derived. This function is the single definition of the A/B table."""
    per_arm = {arm: [r for r in runs if r["arm"] == arm] for arm in ARMS}
    counts = {arm: len(rows) for arm, rows in per_arm.items()}
    if not counts[ARM_ON] or counts[ARM_ON] != counts[ARM_OFF]:
        raise ValueError(f"the arms are not balanced: {counts}")

    def median(arm: str, key: str) -> float | int:
        value = statistics.median(r[key] for r in per_arm[arm])
        return round(value, 1) if isinstance(value, float) else value

    return {
        "incident": (
            "incident #2 — inventory-api error_rate 0.38, with belief-inventory-api v1 "
            "already in the store"
        ),
        "runs_per_arm": counts[ARM_ON],
        "statistic": "median",
        "generated_from": [path.name for path in sorted(ARTIFACTS.glob("run-*.json"))],
        "rows": [
            {
                "metric": label,
                "unit": unit,
                "memory_on": median(ARM_ON, key),
                "memory_off": median(ARM_OFF, key),
            }
            for key, label, unit in METRICS
        ],
    }


def render(table: dict[str, Any]) -> str:
    """The markdown the report carries, generated from the same dict the panel renders."""
    lines = [
        "| Metric | memory on | memory off |",
        "|---|---|---|",
    ]
    for row in table["rows"]:
        unit = f" {row['unit']}" if row["unit"] and row["unit"] != "model-asserted" else ""
        label = row["metric"]
        if row["unit"] == "model-asserted":
            label += " *(model-asserted)*"
        lines.append(f"| {label} | {row['memory_on']}{unit} | {row['memory_off']}{unit} |")
    return "\n".join(lines)


def reproduce() -> int:
    """Re-derive the table from the committed runs and assert every copy of it agrees.

    Three copies exist by necessity -- the raw runs, the JSON the route serves, and the
    markdown a reader sees -- and only the first is evidence. The other two are renderings,
    so this asserts they are renderings *of it* rather than of whatever was true when someone
    last edited them by hand.
    """
    runs = load_runs()
    if not runs:
        print(
            f"FAIL: no run artifacts in {ARTIFACTS.relative_to(REPO)}. Record them first:\n"
            "        .venv/bin/python scripts/verify_counterfactual.py --record",
            file=sys.stderr,
        )
        return 1

    failures = 0
    built = build_table(runs)
    print(f"--> re-derived the table from {len(runs)} committed run artifact(s)")

    if not TABLE.exists():
        print(f"FAIL: {TABLE.relative_to(REPO)} does not exist", file=sys.stderr)
        return 1
    served = json.loads(TABLE.read_text())
    if served != built:
        print(
            f"FAIL: {TABLE.relative_to(REPO)} does not match what the runs derive.\n"
            f"      served: {json.dumps(served, sort_keys=True)}\n"
            f"      runs:   {json.dumps(built, sort_keys=True)}",
            file=sys.stderr,
        )
        failures += 1
    else:
        print(f"    ok  {TABLE.relative_to(REPO)} is what the runs derive")

    if not REPORT.exists():
        print(f"FAIL: {REPORT.relative_to(REPO)} does not exist", file=sys.stderr)
        return failures + 1
    prose = REPORT.read_text()
    if TABLE_START not in prose or TABLE_END not in prose:
        print(
            f"FAIL: {REPORT.relative_to(REPO)} has no {TABLE_START} / {TABLE_END} markers",
            file=sys.stderr,
        )
        return failures + 1
    embedded = prose.split(TABLE_START, 1)[1].split(TABLE_END, 1)[0].strip()
    if embedded != render(built):
        print(
            f"FAIL: the table in {REPORT.relative_to(REPO)} is not the one the runs derive.\n"
            f"      expected:\n{render(built)}\n      found:\n{embedded}",
            file=sys.stderr,
        )
        failures += 1
    else:
        print(f"    ok  {REPORT.relative_to(REPO)}'s table is what the runs derive")

    if failures:
        print(f"\n{failures} check(s) failed.", file=sys.stderr)
        return 1
    print("\n--> the A/B table is reproducible from the committed run artifacts.")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--record",
        action="store_true",
        help="run the live A/B (credentials, real Gemini calls) and write the artifacts",
    )
    parser.add_argument(
        "--runs",
        type=int,
        default=3,
        metavar="N",
        help=(
            "trials per arm when recording (default 3). One trial is two incidents, so N "
            "costs 4N incidents in total. Below 3 there is no median and the report cannot "
            "tell a difference from a single slow run."
        ),
    )
    args = parser.parse_args()

    if not args.record:
        return reproduce()

    if args.runs < 1:
        print("--runs must be at least 1.", file=sys.stderr)
        return 1

    project_id = os.environ.get("GOOGLE_CLOUD_PROJECT")
    pem = os.environ.get(incident.PLANNER_KEY_ENV)
    if not project_id:
        print("GOOGLE_CLOUD_PROJECT is not set.", file=sys.stderr)
        return 1
    if not pem:
        print(f"{incident.PLANNER_KEY_ENV} is not set.", file=sys.stderr)
        return 1
    if not telemetry.configure_tracing(project_id):
        print("tracing did not configure; the spans would not be exported.", file=sys.stderr)
        return 1

    return asyncio.run(record(project_id, load_private_key(pem), args.runs))


if __name__ == "__main__":
    raise SystemExit(main())
