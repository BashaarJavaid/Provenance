"""The SRE/Infra Agent (§5.4): diagnose an infrastructure deviation.

**This is the domain file.** §5.4's generality claim is that adding a domain costs one agent
file and one registry entry and zero lines in the control plane, and item 22 measures it by
counting the lines that had to change *outside* this file. So nothing reusable lives here:
the span plumbing is `_reasoning.py`, the routing map and the graph are `incident.py`, and
the only thing this module knows that they do not is what an infrastructure fault looks like.

It diagnoses against the entity model's config history -- `current_config_version` over
`known_good_version` is the gap incident #1 turns on (§9) -- and emits a hypothesis with the
evidence it rests on. It proposes nothing: §2.1 has the Planner emit the Action, and an agent
that both diagnoses and proposes is an agent that can talk itself into an action.
"""

from __future__ import annotations

from google.adk.agents import LlmAgent
from pydantic import BaseModel, Field

from provenance.agents import _reasoning

OUTPUT_KEY = "diagnosis"
STEP = "diagnosis"
DOMAIN = "infrastructure"
# What this domain covers, in the Orchestrator's vocabulary. Naming the domain was not
# enough: with one domain registered, a model asked to classify "error rate on a service"
# against the bare word "infrastructure" can reasonably decide it is an application concern
# and route it nowhere. Observed live before this line existed.
DOMAIN_SCOPE = (
    "services and the infrastructure they run on: error rates, latency, availability, "
    "capacity, deployments, rollouts and configuration changes"
)


class Diagnosis(BaseModel):
    """What the domain agent hands the Planner. Not an action, and not authority."""

    summary: str = Field(description="What is wrong, in one or two sentences.")
    evidence_refs: list[str] = Field(
        description="Short stable ids for the observations this rests on, e.g. obs-error-rate."
    )
    recommended_action_class: str = Field(
        description="The action class that would address the cause, or NONE if unsure."
    )
    hypotheses_considered: int = Field(
        description="How many distinct causes were genuinely weighed."
    )
    selected_hypothesis: str = Field(
        description="A short snake_case label for the chosen cause, e.g. config_regression."
    )


def build(model: str | object, *, agent_id: str, agent_version: str) -> LlmAgent:
    agent = LlmAgent(
        name="sre_infra_agent",
        model=model,  # type: ignore[arg-type]
        description="Diagnoses infrastructure anomalies against prior belief and config history.",
        instruction=(
            "You are the SRE/Infrastructure agent of an incident-response fleet.\n"
            "A deviation has been reported and routed to you:\n"
            "  service: {trigger_target} (tier {target_tier})\n"
            "  description: {target_description}\n"
            "  signal: {trigger_signal}\n"
            "  observed value: {trigger_observed_value}\n"
            "  observed at: {trigger_observed_at}\n"
            "  currently deployed config version: {current_config_version}\n"
            "  last known-good config version: {known_good_version}\n"
            "  prior beliefs recalled about this service: {recall_summary}\n\n"
            "Diagnose the most likely cause. Weigh more than one -- report how many you "
            "genuinely considered, not how many you can name.\n"
            "If the deployed config version is ahead of the last known-good one and the "
            "deviation began after it, a configuration regression is the leading candidate.\n"
            "Recommend an action class only from this list: {known_action_classes}. "
            "Recommend NONE if the evidence does not support any of them.\n"
            "Do not propose an action; another agent does that. Diagnose only."
        ),
        output_schema=Diagnosis,
        output_key=OUTPUT_KEY,
    )
    _reasoning.attach(
        agent, agent_id=agent_id, agent_version=agent_version, step=STEP, output_key=OUTPUT_KEY
    )
    return agent
