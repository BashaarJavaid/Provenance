"""The Remediation Planner (§5.5): one diagnosis in, exactly one typed Action out.

§5.5: "Converts a diagnosis into exactly one typed Action (§3.1) with declared blast radius,
reversibility, evidence references, and a success predicate. Never free-form text."

`output_schema` is how "never free-form text" becomes structural rather than instructed --
the model cannot return prose because the response is constrained to the schema. What it
returns is still only a *proposal*: `action.validate()` overrules the declared tier against
the entity model and the declared reversibility and blast radius against the tool registry
(item 6), so a Planner that understates any of the three fails validation rather than
lowering its own risk score. §3.1's "not vibes", enforced downstream of this file.

`proposed_by` is templated in from the registry record rather than invented, because the
gateway checks it against the presented credential and a mismatch denies at
`stage="identity"` (item 7). The model copies a string; if it mangles it, the denial is the
version-binding check working.

The private key never appears here: `incident.py` loads it once per process and calls
`credentials.mint()` itself. This module builds an agent and reshapes its output, nothing more.

Two feedback slots, both empty on a first pass and both filled by the control loop, never by an
agent: `{malformed_feedback}` is §7.1's schema rejection (item 9) and `{refutation_feedback}` is
§7.2's refuted remediation (item 20). They stay separate because they say different things -- one
is "that was not a valid action", the other is "that action ran and did not work" -- and a Planner
that cannot tell them apart cannot respond to either.
"""

from __future__ import annotations

from google.adk.agents import LlmAgent
from pydantic import BaseModel, Field

from provenance.agents import _reasoning

OUTPUT_KEY = "proposal"
STEP = "planning"

# §3.1's eight fields, and the two telemetry counters every agent in this package reports.
# The eight are stripped back out before `action.validate()` sees them -- the Action has
# exactly eight fields and a ninth would be a channel onto the determinism boundary.
ACTION_FIELDS = (
    "action_class",
    "target",
    "target_tier",
    "blast_radius",
    "reversible",
    "evidence_refs",
    "success_predicate",
    "proposed_by",
)


class Proposal(BaseModel):
    """The Planner's structured emission. A candidate Action, not an Action."""

    action_class: str = Field(description="Must name a tool in the registry.")
    target: str = Field(description="Must name an entity of the kind that tool expects.")
    target_tier: str = Field(description="tier1, tier2 or tier3, as the entity model records it.")
    blast_radius: str = Field(description="single-service, multi-service or org-wide.")
    reversible: bool = Field(description="Whether the tool's effects can be undone.")
    evidence_refs: list[str] = Field(description="The diagnosis's evidence ids.")
    success_predicate: str = Field(
        description=(
            "One sentence, checkable against observable telemetry after execution, naming a "
            "metric, a threshold and a time window. Declared before execution and never revised."
        )
    )
    proposed_by: str = Field(description="This agent's id and version, exactly as given.")
    hypotheses_considered: int = Field(description="How many candidate actions were weighed.")
    selected_hypothesis: str = Field(description="A short snake_case label for the chosen plan.")


def build(model: str | object, *, agent_id: str, agent_version: str) -> LlmAgent:
    agent = LlmAgent(
        name="remediation_planner",
        model=model,  # type: ignore[arg-type]
        description="Converts a diagnosis into exactly one typed Action.",
        instruction=(
            "You are the Remediation Planner of an incident-response fleet.\n"
            "A domain agent has diagnosed an incident:\n"
            "  service: {trigger_target} (tier {target_tier})\n"
            "  currently deployed config version: {current_config_version}\n"
            "  last known-good config version: {known_good_version}\n"
            "  nominal (healthy) error rate: {nominal_error_rate} "
            "({nominal_error_rate_pct}%)\n"
            "  diagnosis: {diagnosis_summary}\n\n"
            "Emit exactly one action that addresses the diagnosed cause.\n"
            "  - action_class must be one of: {known_action_classes}\n"
            "  - target must be the entity the diagnosis is about\n"
            "  - target_tier, blast_radius and reversible must be reported truthfully. They "
            "are checked against the entity model and the tool registry, and an "
            "understatement fails validation rather than lowering the action's risk.\n"
            "  - evidence_refs must be the diagnosis's own evidence ids\n"
            "  - proposed_by must be exactly: {planner_identity}\n"
            "  - success_predicate is declared now and checked after execution. Name the "
            "metric, the threshold and the window. It must be checkable against the target "
            "service's observable state -- its error rate and its deployed config version -- "
            "and must state a concrete numeric threshold, because a verification agent will "
            "be shown only those measurements and your sentence. The threshold you name must "
            "be strictly above the nominal error rate given above: a remediation that fully "
            "succeeds returns the service to exactly that value, so a threshold at it is "
            "unsatisfiable no matter how well the remediation worked. State every value "
            "literally rather than by reference -- the verification agent is shown the "
            "deployed config version but not what 'known-good' refers to, so write \"is "
            '{known_good_version}" and never "matches the last known-good version".\n\n'
            "Outside the success predicate, do not carry a version number in any field: the "
            "executor reads the known-good version from the entity model, so a version in "
            "your sentence is something to be checked and never something to be obeyed.\n"
            "{malformed_feedback}"
            "{refutation_feedback}"
        ),
        output_schema=Proposal,
        output_key=OUTPUT_KEY,
    )
    _reasoning.attach(
        agent, agent_id=agent_id, agent_version=agent_version, step=STEP, output_key=OUTPUT_KEY
    )
    return agent


def to_proposal(output: dict[str, object]) -> dict[str, object]:
    """The eight §3.1 fields, with this package's two telemetry counters dropped."""
    return {field: output[field] for field in ACTION_FIELDS if field in output}
