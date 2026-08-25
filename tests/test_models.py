"""The per-role model strings are config, but the *roles* are architecture (§5).

A swapped model string is a one-line change by design (ROADMAP item 1). A swapped *role*
mapping -- verification quietly running on the same model that produced the thing being
verified -- is not, and is the kind of change that reads as a tidy-up in a diff.
"""

from __future__ import annotations

from provenance import models


def test_the_five_roles_are_the_models_actually_deployed() -> None:
    # Gemini 3.5 Pro does not exist for this project (ROADMAP item 1), so the reasoning
    # roles are on GA 2.5 Pro rather than a preview model that can move during judging.
    assert models.ORCHESTRATOR == "gemini-2.5-pro"
    assert models.DOMAIN == "gemini-2.5-pro"
    assert models.PLANNER == "gemini-2.5-pro"
    assert models.VERIFICATION == "gemini-3.5-flash"
    # §5.9's Memory Analyst (item 23), which runs from a seeder and not per incident.
    assert models.ANALYST == "gemini-2.5-pro"


def test_verification_does_not_run_on_the_model_it_verifies() -> None:
    """§7.2's honesty rests on the checker not being the thing checked."""
    assert models.VERIFICATION not in (models.DOMAIN, models.PLANNER)


def test_gemini_3x_is_reachable_because_the_endpoint_is_global() -> None:
    # Item 1's finding: a regional probe 404s on 3.x models that do in fact serve.
    assert models.LOCATION == "global"
