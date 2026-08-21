"""The tool registry — what actions exist, and what is true about them (item 6).

`ARCHITECTURE.md` §3.1: an Action's `action_class` "must exist in the tool registry", and its
declared `reversible` and `blast_radius` are "validated against the tool schema — the tool
registry knows that `DISABLE_COMPLIANCE_CHECKS` is irreversible and org-wide, so a Planner
claiming otherwise fails validation." This module is that registry, and those two fields are
why it is authoritative rather than descriptive: `THREAT_MODEL.md`'s assumption row states it
directly — "the tool registry, not the Planner, is authoritative for reversibility and blast
radius". `provenance/action.py` performs the comparison.

Unlike the *agent* registry (`provenance/registry.py`), this one is an in-code constant rather
than a Firestore collection. Standing changes mid-run and must be read at request time (§1.1
property 4); a tool's reversibility does not change at all. Hand-authored and reviewed is
exactly what `THREAT_MODEL.md` assumes of it. Reasoning in `docs/adr/ADR-011`.

Two entries, because §4.2 names two action classes. A third would be a string item 7's risk
table has to either honour or delete — the same trap ADR-010 avoided when it kept
`registry.AGENTS[*].tool_scope` down to the names the docs actually use.

What this module deliberately does not do: carry `base[action_class]` (item 7 — every risk
component belongs together in the table, and a base score here would put the determinism
boundary in two places), emit spans, or read Firestore.
"""

from __future__ import annotations

from dataclasses import dataclass

from provenance.telemetry import BlastRadius, TargetKind

# Every field here is a fact about the tool, never about one invocation of it. `target_kind` is
# what ADR-009 meant by "item 6 validates a target against a tool schema that names which it
# expects": it selects the entity collection the target must be found in.


@dataclass(frozen=True)
class Tool:
    """One entry in the tool registry. §3.1 validates a proposed Action against this."""

    action_class: str
    target_kind: TargetKind
    # Authoritative, not advisory: a Planner that declares otherwise fails validation.
    reversible: bool
    blast_radius: BlastRadius


TOOLS: tuple[Tool, ...] = (
    Tool(
        action_class="ROLLBACK_CONFIG",
        target_kind="service",
        reversible=True,
        blast_radius="single-service",
    ),
    Tool(
        action_class="DISABLE_COMPLIANCE_CHECKS",
        target_kind="supplier",
        reversible=False,
        blast_radius="org-wide",
    ),
)

_BY_ACTION_CLASS = {tool.action_class: tool for tool in TOOLS}


def tool_for(action_class: str) -> Tool:
    """The tool an `action_class` names. Raises `KeyError` if no such tool exists.

    Raising rather than returning `None` is the same posture as `registry.get_agent()`: a
    fabricated tool must not be one forgotten `if tool:` away from reaching the risk table.
    `action.validate()` catches the `KeyError` and raises `UnknownTool`.
    """
    return _BY_ACTION_CLASS[action_class]
