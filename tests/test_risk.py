"""ROADMAP item 7's `verify:` line, first half: the risk table is a pure lookup.

`ARCHITECTURE.md` §10's Risk-table row -- "Table-driven tests over every `action_class` x
tier x blast x reversibility combination; assert the two worked examples score 2 and 11
exactly" -- is `test_every_combination_sums_to_its_components` and the two worked-example
tests below.

The exhaustive sweep matters more than it looks. It is not checking arithmetic Python
already does; it is checking that no combination reaches a lookup that has no entry, which
is how a fifth tier or a third tool would fail -- at authorization time, in production,
fail-*open* if the KeyError were ever caught somewhere generic.

Point values are written as literals rather than read from the module's own tables, the
same reason `tests/test_telemetry_schema.py` spells attribute keys out: asserting against
the constant would pass a changed constant straight through.
"""

from __future__ import annotations

import inspect
import types
from itertools import product
from typing import Any, Union, get_args, get_origin, get_type_hints

import pytest

from provenance import action, risk, tools
from provenance.telemetry import BlastRadius, Tier


def an_action(**overrides: Any) -> action.Action:
    """A structurally valid Action. Built directly, not through `validate()`.

    The sweep needs combinations the entity model cannot produce -- `ROLLBACK_CONFIG` on a
    tier1 target, say -- and `validate()`'s whole job is to reject those. The table must
    still be total over them: it is a lookup, and a lookup with a hole is a crash.
    """
    fields: dict[str, Any] = {
        "action_class": "ROLLBACK_CONFIG",
        "target": "inventory-api",
        "target_tier": "tier2",
        "blast_radius": "single-service",
        "reversible": True,
        "evidence_refs": ("ev-118",),
        "success_predicate": "error_rate < 0.05 within 10m",
        "proposed_by": "remediation-planner@v1",
    }
    return action.Action(**(fields | overrides))


# --- §4.2's two worked examples -----------------------------------------------------------


def test_the_rollback_worked_example_scores_exactly_2() -> None:
    # §4.2: ROLLBACK_CONFIG(inventory-api, v42->v41) | 1 | +1 | +0 | +0 | **2** | auto-approve
    scored = risk.score(an_action())
    assert (scored.base, scored.criticality, scored.blast, scored.irreversibility) == (1, 1, 0, 0)
    assert scored.score == 2
    assert risk.band(scored.score) == "APPROVE"


def test_the_disable_compliance_worked_example_scores_exactly_11() -> None:
    # §4.2: DISABLE_COMPLIANCE_CHECKS(SUP-042) | 4 | +2 | +2 | +3 | **11** | human approval
    scored = risk.score(
        an_action(
            action_class="DISABLE_COMPLIANCE_CHECKS",
            target="SUP-042",
            target_tier="tier1",
            blast_radius="org-wide",
            reversible=False,
        )
    )
    assert (scored.base, scored.criticality, scored.blast, scored.irreversibility) == (4, 2, 2, 3)
    assert scored.score == 11
    assert risk.band(scored.score) == "HOLD"


def test_both_worked_examples_validate_before_they_are_scored() -> None:
    # The scores above are only meaningful because every field feeding them was checked
    # against an authority that is not the Planner (§3.1). Item 6 asserts this too; asserted
    # again here because it is the premise the whole table rests on.
    rollback = action.validate(
        {
            "action_class": "ROLLBACK_CONFIG",
            "target": "inventory-api",
            "target_tier": "tier2",
            "blast_radius": "single-service",
            "reversible": True,
            "evidence_refs": ["ev-118"],
            "success_predicate": "error_rate < 0.05 within 10m",
            "proposed_by": "remediation-planner@v1",
        }
    )
    disable = action.validate(
        {
            "action_class": "DISABLE_COMPLIANCE_CHECKS",
            "target": "SUP-042",
            "target_tier": "tier1",
            "blast_radius": "org-wide",
            "reversible": False,
            "evidence_refs": ["ev-140"],
            "success_predicate": "compliance_checks_enabled == false",
            "proposed_by": "remediation-planner@v1",
        }
    )
    assert risk.score(rollback).score == 2
    assert risk.score(disable).score == 11


# --- the exhaustive sweep (§10's Risk-table row) ------------------------------------------

COMBINATIONS = list(
    product(sorted(risk.BASE), get_args(Tier), get_args(BlastRadius), (True, False))
)


@pytest.mark.parametrize(("action_class", "tier", "blast", "reversible"), COMBINATIONS)
def test_every_combination_sums_to_its_components(
    action_class: str, tier: Tier, blast: BlastRadius, reversible: bool
) -> None:
    scored = risk.score(
        an_action(
            action_class=action_class,
            target_tier=tier,
            blast_radius=blast,
            reversible=reversible,
        )
    )
    expected = {"ROLLBACK_CONFIG": 1, "DISABLE_COMPLIANCE_CHECKS": 4}[action_class]
    expected += {"tier1": 2, "tier2": 1, "tier3": 0}[tier]
    expected += {"org-wide": 2, "multi-service": 1, "single-service": 0}[blast]
    expected += 0 if reversible else 3
    assert scored.score == expected
    # telemetry.set_risk() refuses to emit a score that isn't its parts; hold the same line here.
    assert scored.score == (
        scored.base + scored.criticality + scored.blast + scored.irreversibility
    )


def test_the_sweep_covers_every_combination_that_exists() -> None:
    # 2 tools x 3 tiers x 3 blast radii x 2 reversibilities. If a vocabulary grows and this
    # number does not, the sweep silently stopped being exhaustive.
    assert len(COMBINATIONS) == 36


# --- the bands (§4.2) ---------------------------------------------------------------------


@pytest.mark.parametrize(
    ("total", "outcome"),
    [
        (0, "APPROVE"),
        (3, "APPROVE"),
        (4, "APPROVE_NOTIFY"),
        (6, "APPROVE_NOTIFY"),
        (7, "HOLD"),
        (11, "HOLD"),
        (99, "HOLD"),
    ],
)
def test_the_bands_are_0_3_4_6_and_7_up(total: int, outcome: str) -> None:
    assert risk.band(total) == outcome


def test_the_table_never_denies() -> None:
    # A denial is about who is asking (identity, registry, tool scope), never about the score.
    # The score's worst answer is "a human decides" -- see gateway.py's stage vocabulary.
    assert {risk.band(total) for total in range(40)} == {"APPROVE", "APPROVE_NOTIFY", "HOLD"}


# --- structural guards --------------------------------------------------------------------


def test_every_tool_has_a_base_score_and_no_extras() -> None:
    # A third tool shipping without a base value would raise KeyError inside the gateway --
    # at authorization time, on a real proposal. This fails at build time instead.
    assert set(risk.BASE) == {tool.action_class for tool in tools.TOOLS}


def test_the_component_tables_are_total_over_their_vocabularies() -> None:
    assert set(risk.CRITICALITY) == set(get_args(Tier))
    assert set(risk.BLAST) == set(get_args(BlastRadius))
    assert set(risk.IRREVERSIBILITY) == {True, False}


def test_no_llm_number_can_enter_the_table() -> None:
    # §4.1: a deterministic decision "may not consume a number an LLM produced". score() takes
    # a validated Action and nothing else -- no confidence, no model output, no free parameter.
    parameters = list(inspect.signature(risk.score).parameters)
    assert parameters == ["action"]
    assert get_type_hints(risk.score)["action"] is action.Action


def test_no_function_here_returns_an_optional_score() -> None:
    # The same structural guard as items 5 and 6: a forgotten `if scored:` fails open, and a
    # missing score at the gateway means an action reaching an outcome with no arithmetic.
    for name, fn in vars(risk).items():
        if not inspect.isfunction(fn) or fn.__module__ != risk.__name__:
            continue
        returns = get_type_hints(fn).get("return")
        if get_origin(returns) in (Union, types.UnionType):
            args = get_args(returns)
            assert not (risk.RiskScore in args and type(None) in args), name
