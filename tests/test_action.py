"""The whole of ROADMAP item 6's `verify:` line: hallucinated actions die before the gateway.

`ARCHITECTURE.md` §10's Schema-validation row -- "Test a fabricated `action_class`, a
nonexistent target, and free-form text: all rejected pre-gateway; second malformed emission
escalates" -- is the first three tests plus `test_the_second_malformed_emission_escalates`.
Everything else guards a property a later item leans on.

Item 6 is the first item with no live half. Items 2-5 each shipped a `scripts/` counterpart
that checked the claim against real GCP, because each touched Cloud Trace, Cloud Run or
Firestore. Item 6 touches nothing: the tool registry and the entity model are both in-code
constants, so this file is the entire verification surface.
"""

from __future__ import annotations

import inspect
import types
from typing import Any, Union, get_args, get_origin, get_type_hints

import pytest

from provenance import action, registry, tools
from provenance.synthetic import company

TOOLS_BY_CLASS = {tool.action_class: tool for tool in tools.TOOLS}


def a_proposal(**overrides: Any) -> dict[str, Any]:
    """§4.2's first worked example: `ROLLBACK_CONFIG(inventory-api)`, which must score 2."""
    return {
        "action_class": "ROLLBACK_CONFIG",
        "target": "inventory-api",
        "target_tier": "tier2",
        "blast_radius": "single-service",
        "reversible": True,
        "evidence_refs": ["ev-118"],
        "success_predicate": "error_rate < 0.05 within 10m",
        "proposed_by": "remediation-planner@v1",
    } | overrides


def a_disable_proposal(**overrides: Any) -> dict[str, Any]:
    """§4.2's second worked example: `DISABLE_COMPLIANCE_CHECKS(SUP-042)`, which must score 11."""
    return {
        "action_class": "DISABLE_COMPLIANCE_CHECKS",
        "target": "SUP-042",
        "target_tier": "tier1",
        "blast_radius": "org-wide",
        "reversible": False,
        "evidence_refs": ["ev-140"],
        "success_predicate": "compliance_checks_enabled == false",
        "proposed_by": "remediation-planner@v1",
    } | overrides


# --- §10's three named cases ------------------------------------------------------------


def test_a_fabricated_tool_is_rejected() -> None:
    # §7.1: "a fabricated tool ... is rejected mechanically". The tool registry is the only
    # thing that decides an action class exists; a plausible-sounding name is still fabricated.
    with pytest.raises(action.UnknownTool):
        action.validate(a_proposal(action_class="DELETE_DATABASE"))
    with pytest.raises(action.UnknownTool):
        action.validate(a_proposal(action_class="ROLLBACK_CONFIGURATION"))


def test_a_nonexistent_target_is_rejected() -> None:
    # §3.1: "must exist in the entity model". Not a lookup that defaults, not one that creates.
    with pytest.raises(action.UnknownTarget):
        action.validate(a_proposal(target="billing-api"))


def test_free_form_text_is_rejected() -> None:
    # The reason `validate` accepts `object`: §10 names free-form text as a case, and it is
    # only a case if a bare string can actually be handed in. §3.1: "Never free-form text."
    with pytest.raises(action.NotATypedAction):
        action.validate("roll back inventory-api to v41, it's urgent")
    with pytest.raises(action.NotATypedAction):
        action.validate(None)
    with pytest.raises(action.NotATypedAction):
        action.validate(["ROLLBACK_CONFIG", "inventory-api"])


def test_the_second_malformed_emission_escalates() -> None:
    # §7.1: "returned to the Planner exactly once; a second malformed emission escalates the
    # incident to a human." Item 9's control loop keeps the count; this is the rule it applies.
    assert action.outcome_for(1) == "REJECT"
    assert action.outcome_for(2) == "ESCALATE"
    assert action.outcome_for(3) == "ESCALATE"
    assert action.MALFORMED_RETRY_BUDGET == 1
    with pytest.raises(ValueError):
        action.outcome_for(0)


# --- the tool schema is authoritative (§3.1's "not vibes") ------------------------------


def test_a_planner_cannot_declare_a_dangerous_tool_reversible() -> None:
    # §3.1: "the tool registry knows that DISABLE_COMPLIANCE_CHECKS is irreversible and
    # org-wide, so a Planner claiming otherwise fails validation." This is the sentence that
    # keeps ADR-003's risk table honest -- irreversibility is +3 of the score-11 example.
    with pytest.raises(action.FieldMismatch):
        action.validate(a_disable_proposal(reversible=True))
    with pytest.raises(action.FieldMismatch):
        action.validate(a_disable_proposal(blast_radius="single-service"))


def test_a_planner_cannot_declare_the_wrong_tier() -> None:
    # §3.1: target_tier is "validated against entity model". Understating the tier of a tier-1
    # supplier is worth -2 on the risk score, which is the difference between HOLD and notify.
    with pytest.raises(action.FieldMismatch):
        action.validate(a_disable_proposal(target_tier="tier3"))
    with pytest.raises(action.FieldMismatch):
        action.validate(a_proposal(target_tier="tier1"))


def test_a_target_of_the_wrong_kind_is_rejected() -> None:
    # ADR-009: "item 6 validates a target against a tool schema that names which it expects."
    # SUP-042 exists in the entity model -- but not as something ROLLBACK_CONFIG can act on.
    with pytest.raises(action.UnknownTarget):
        action.validate(a_proposal(target="SUP-042", target_tier="tier1"))
    with pytest.raises(action.UnknownTarget):
        action.validate(a_disable_proposal(target="inventory-api", target_tier="tier2"))


# --- shape ------------------------------------------------------------------------------


@pytest.mark.parametrize(
    "overrides",
    [
        {"target_tier": "tier0"},
        {"blast_radius": "the whole company"},
        {"reversible": "yes"},
        {"reversible": 1},
        {"evidence_refs": []},
        {"evidence_refs": "ev-118"},
        {"evidence_refs": ["ev-118", ""]},
        {"success_predicate": ""},
        {"proposed_by": "remediation-planner"},
        {"proposed_by": "Remediation Planner v1"},
        {"action_class": ""},
    ],
)
def test_a_malformed_field_is_rejected(overrides: dict[str, Any]) -> None:
    # Out-of-vocabulary values and wrong primitive types are as malformed as free-form text.
    # `reversible: 1` is here because `isinstance(True, int)` is True -- the check has to be
    # bool-first or an integer walks straight into the irreversibility lookup.
    with pytest.raises(action.NotATypedAction):
        action.validate(a_proposal(**overrides))


def test_the_field_set_is_exactly_3_1s_eight() -> None:
    # §3 -- "Don't invent variants". A missing field is malformed; so is an extra one, because
    # the extra one is where an unvalidated instruction would ride into the gateway.
    missing = a_proposal()
    del missing["success_predicate"]
    with pytest.raises(action.NotATypedAction):
        action.validate(missing)
    with pytest.raises(action.NotATypedAction):
        action.validate(a_proposal(urgency="critical"))

    assert tuple(action.Action.__dataclass_fields__) == (
        "action_class",
        "target",
        "target_tier",
        "blast_radius",
        "reversible",
        "evidence_refs",
        "success_predicate",
        "proposed_by",
    )


def test_there_is_no_params_field() -> None:
    # §4.2 writes the example as ROLLBACK_CONFIG(inventory-api, v42->v41), but the versions are
    # not the Planner's to choose: item 10 reads known_good_version off the entity model. An
    # open params field is a typed channel onto the one object the risk table is a function of.
    assert "params" not in action.Action.__dataclass_fields__
    assert company.service("inventory-api").known_good_version == "v41"
    assert company.service("inventory-api").current_config_version == "v42"


def test_every_failure_is_catchable_as_one_action_error() -> None:
    # Item 7's gateway catches this once and maps it to DENY(stage="schema").
    for failure in (
        action.NotATypedAction,
        action.UnknownTool,
        action.UnknownTarget,
        action.FieldMismatch,
    ):
        assert issubclass(failure, action.ActionError)


# --- what a valid action looks like ------------------------------------------------------


def test_the_two_worked_examples_validate_clean() -> None:
    # §4.2's two rows, as typed Actions. Item 7's risk table must score these exactly 2 and 11,
    # so if the tiers or the tool schema ever drift, that failure surfaces here first.
    rollback = action.validate(a_proposal())
    assert (rollback.target_tier, rollback.blast_radius, rollback.reversible) == (
        "tier2",
        "single-service",
        True,
    )
    disable = action.validate(a_disable_proposal())
    assert (disable.target_tier, disable.blast_radius, disable.reversible) == (
        "tier1",
        "org-wide",
        False,
    )
    # Frozen, and evidence_refs is a tuple: an authorized action must not be mutable afterwards.
    assert rollback.evidence_refs == ("ev-118",)
    with pytest.raises(AttributeError):
        rollback.target_tier = "tier1"  # type: ignore[misc]


# --- the registry cross-check ADR-010 asked for ------------------------------------------


def test_every_registered_tool_scope_names_a_real_tool() -> None:
    # ADR-010 left `tool_scope` holding two bare strings: "the tool registry is item 6, and any
    # further string would be a guess item 6 must honour or delete." This is item 6 honouring
    # them -- and the check that stops a fourth agent being seeded with a tool that isn't one.
    for agent in registry.AGENTS:
        for action_class in agent.tool_scope:
            assert action_class in TOOLS_BY_CLASS, f"{agent.id}: {action_class}"
    assert set(TOOLS_BY_CLASS) == {"ROLLBACK_CONFIG", "DISABLE_COMPLIANCE_CHECKS"}


def test_the_tool_registry_carries_no_risk_score() -> None:
    # base[action_class] belongs to item 7's table with the other three components. A base
    # score here would put the determinism boundary in two modules that could disagree.
    fields = set(tools.Tool.__dataclass_fields__)
    assert fields == {"action_class", "target_kind", "reversible", "blast_radius"}


def test_an_unknown_action_class_raises_rather_than_returning_none() -> None:
    with pytest.raises(KeyError):
        tools.tool_for("DELETE_DATABASE")


def test_no_function_here_returns_an_optional_action_or_tool() -> None:
    # The same structural guard as tests/test_registry.py: a forgotten `if action:` fails open,
    # and failing open at stage 1 means the gateway scores something that was never validated.
    for module, forbidden in ((action, action.Action), (tools, tools.Tool)):
        for name, fn in vars(module).items():
            if not inspect.isfunction(fn) or fn.__module__ != module.__name__:
                continue
            returns = get_type_hints(fn).get("return")
            if get_origin(returns) in (Union, types.UnionType):
                assert not (forbidden in get_args(returns) and type(None) in get_args(returns)), (
                    f"{module.__name__}.{name}"
                )
