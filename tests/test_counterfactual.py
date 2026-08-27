"""Item 32's `verify:` line, in CI: the A/B table is reproducible from the committed runs.

The check itself lives in `scripts/verify_counterfactual.py` so that a person can run it as
one command, and this calls that command rather than re-implementing it -- a second copy of
the comparison could pass while the one anybody actually runs failed.

It is a subprocess and not an import on purpose: the exit code is the contract, and running
the script the way a human runs it is what this file is for.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
SCRIPT = REPO / "scripts" / "verify_counterfactual.py"
ARTIFACTS = REPO / "docs" / "counterfactual"
TABLE = REPO / "provenance" / "web" / "counterfactual.json"


def test_the_ab_table_is_reproducible_from_the_committed_run_artifacts() -> None:
    """The item's line, mechanically. Red if the report or the served table drifts."""
    done = subprocess.run(
        [sys.executable, str(SCRIPT)], capture_output=True, text=True, cwd=REPO, check=False
    )
    assert done.returncode == 0, done.stdout + done.stderr


def test_the_served_table_is_what_the_route_and_the_panel_read() -> None:
    """It ships inside the package, because the image copies `provenance/` and not `docs/`."""
    served = json.loads(TABLE.read_text())
    assert served["runs_per_arm"] >= 1
    assert [row["metric"] for row in served["rows"]] == [
        "wall-clock",
        "model calls",
        "input tokens",
        "output tokens",
        "hypotheses considered",
    ]


@pytest.mark.parametrize("arm", ["memory-on", "memory-off"])
def test_both_arms_reached_the_same_belief_version(arm: str) -> None:
    """The ablation moved one variable.

    Both arms supersede to v2: the belief was in the store for both, and only *reading* it was
    disabled. An arm ending at v1 would mean the run had no belief to begin with, and an arm
    with no belief at all would mean the commit had been disabled too -- either way the table
    would be comparing two things instead of one, and its delta would be unattributable.
    """
    runs = [json.loads(p.read_text()) for p in sorted(ARTIFACTS.glob(f"run-*-{arm}.json"))]
    assert runs, f"no committed runs for {arm}"
    for run in runs:
        assert run["outcome"] == "RESOLVED"
        assert run["belief_version"] == 2
