"""The Memory Analyst (§5.9): propose a class-level generalization (ROADMAP item 23).

Deferred here from item 14, which had promised "the Memory Analyst recommends; the engine
decides" and then found it had nothing for an Analyst to do: deriving a *status* from a
confirmed rollback is not a model's job, because the control loop already knows deterministically
what a confirmed rollback teaches (`incident.BELIEF_STATUS` is a constant). §6.2 is the first
thing that genuinely needs one. Reading three entity beliefs and writing the sentence they have
in common is an extraction problem, which §4.4 puts on the model side of the boundary.

**It recommends and never commits, and it never asserts a number.** What it returns is a class
name and one sentence; every other field of the belief that results is the Policy Engine's:
`derived_from` is what the caller selected mechanically, the evidence set is derived from those
constituents inside §2.2, and the confidence is §4.3 capped by §6.2. The prompt says so, and
`Generalization` has no field it could put a number in even if it wanted to.

Unlike the domain agents this is not a `DOMAINS` entry and runs in no incident. It is invoked
once, by `scripts/seed_class_belief.py`, which is why nothing in `incident.py` changed for it.
"""

from __future__ import annotations

from google.adk.agents import LlmAgent
from pydantic import BaseModel, Field

from provenance.agents import _reasoning

OUTPUT_KEY = "generalization"
STEP = "generalization"
AGENT_ID = "memory-analyst"
AGENT_VERSION = "v1"


class Generalization(BaseModel):
    """§6.2's two model-authored fields, and the two `_reasoning.attach()` reads for the span.

    No confidence field, deliberately: §5.9 says the Analyst never asserts one, and the surest
    way to keep that true is to give it nowhere to write it.
    """

    belief_class: str = Field(
        description="A short dotted label for the class, e.g. service.config_deploy."
    )
    statement: str = Field(
        description="One sentence stating what is true of this class of entity. It must be "
        "checkable against a future entity of the same class, and must not name any of the "
        "specific entities it was derived from."
    )
    hypotheses_considered: int = Field(
        description="How many distinct shared signatures were genuinely weighed."
    )
    selected_hypothesis: str = Field(
        description="A short snake_case label for the signature chosen, e.g. config_deploy."
    )


def build(model: str | object, *, agent_id: str, agent_version: str) -> LlmAgent:
    agent = LlmAgent(
        name="memory_analyst",
        model=model,  # type: ignore[arg-type]
        description="Proposes a class-level generalization over entity beliefs that share a shape.",
        instruction=(
            "You are the Memory Analyst of an incident-response fleet.\n"
            "These entity beliefs are what the organization currently believes. They were "
            "selected because they share a status, and your job is to say what else they "
            "share:\n\n"
            "{constituents}\n\n"
            "What that status records:\n"
            "{status_meaning}\n\n"
            "Propose ONE class-level generalization covering all of them.\n"
            "  - The statement must be true of an entity of this class the fleet has never "
            "seen. Name the class of entity and the observable pattern, never the specific "
            "entities above.\n"
            "  - A class is what the entities *are* -- their kind and their tier -- never an "
            "incidental feature of their names or descriptions. Three services whose names "
            "share a word do not form a class; three tier-2 services do.\n"
            "  - It must be one sentence, and checkable: name what correlates with what, and "
            "over what window, rather than restating that these entities have a status.\n"
            "  - Every term in it must come from what you were shown. You have each entity's "
            "kind, tier, description and the status they share, and nothing else. Do not "
            "introduce a property you were not given -- a sentence resting on something "
            "nobody observed is a belief this organization would hold on no evidence.\n"
            "  - Weigh more than one candidate signature -- report how many you genuinely "
            "considered, not how many you can name.\n\n"
            "You are recommending, not deciding. You do not state a confidence: the number is "
            "computed downstream from the evidence these beliefs already rest on and is capped "
            "below the weakest of them. A class belief is ADVISORY ONLY -- it may change what "
            "a diagnosis looks at first, and it can never authorize an action or support a "
            "belief about a specific entity. Do not recommend an action."
        ),
        output_schema=Generalization,
        output_key=OUTPUT_KEY,
    )
    _reasoning.attach(
        agent, agent_id=agent_id, agent_version=agent_version, step=STEP, output_key=OUTPUT_KEY
    )
    return agent
