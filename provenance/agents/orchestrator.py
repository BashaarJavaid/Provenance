"""The Orchestrator (§5.3): classify the trigger, so the control loop can route it.

§5.3 gives this role three verbs -- classify, recall, route -- of which only the first is
reasoning. Recall is a store lookup (§6.6, item 16) and routing is a registry lookup, and
both belong in `incident.py` where they can be checked. What is left here is the one
judgement a model is actually for: given a deviation, which domain owns it.

The domain vocabulary is passed in rather than hardcoded, because `incident.DOMAIN_AGENTS`
is the single place a domain becomes routable. A classification outside that vocabulary is
not an error here -- it is an UNROUTABLE incident, which is a fact the trace should carry
rather than a crash.
"""

from __future__ import annotations

from google.adk.agents import LlmAgent
from pydantic import BaseModel, Field

from provenance.agents import _reasoning

OUTPUT_KEY = "classification"
STEP = "classification"


class Classification(BaseModel):
    """What the Orchestrator emits. `domain` is the only field anything acts on."""

    domain: str = Field(description="The domain that owns this deviation.")
    hypotheses_considered: int = Field(
        description="How many domains were genuinely weighed before choosing."
    )
    selected_hypothesis: str = Field(description="A short label for the chosen reading.")


def build(
    model: str | object,
    *,
    agent_id: str,
    agent_version: str,
    domains: tuple[tuple[str, str], ...],
) -> LlmAgent:
    """`domains` is (name, scope) pairs. A name alone is not a vocabulary a model can aim at."""
    agent = LlmAgent(
        name="orchestrator",
        model=model,  # type: ignore[arg-type]
        description="Classifies an incoming deviation into the domain that owns it.",
        instruction=(
            "You are the Orchestrator of an incident-response fleet.\n"
            "A monitored deviation has been reported:\n"
            "  target: {trigger_target}\n"
            "  signal: {trigger_signal}\n"
            "  observed value: {trigger_observed_value}\n"
            "  observed at: {trigger_observed_at}\n"
            "  target description: {target_description}\n"
            "  target tier: {target_tier}\n\n"
            "Classify it into exactly one of these domains, using the exact name given:\n"
            + "".join(f"  {name} -- {scope}\n" for name, scope in domains)
            + "Choose the domain whose scope covers the deviation, and answer with one of "
            "the names above verbatim.\n"
            "Only if the deviation plainly falls outside every scope listed, name a "
            "different domain instead -- the incident then ends unhandled rather than being "
            "sent to an agent that cannot diagnose it. Do not use this to express "
            "uncertainty about the cause: which domain owns a deviation is a separate "
            "question from what went wrong."
        ),
        output_schema=Classification,
        output_key=OUTPUT_KEY,
    )
    _reasoning.attach(
        agent, agent_id=agent_id, agent_version=agent_version, step=STEP, output_key=OUTPUT_KEY
    )
    return agent
