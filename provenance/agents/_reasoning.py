"""Attaching §8.1's `provenance.reasoning.chain` span to an ADK agent (item 9).

Item 2 defined this shape and shipped it with no emitter, because until a fleet existed
there was nothing to record. This module is its first caller.

The span has to *wrap* the model call rather than follow it -- a duration recorded after the
fact is not a duration -- so it is opened in `before_agent_callback` and closed in
`after_agent_callback`, with token counts collected from the response in between. That is
three callbacks for one span, and it is still the cheapest honest option: emitting a
zero-length span afterwards would put a wrong number in the one stream item 32's
counterfactual measures.

ADK invokes these by keyword (`callback_context=`, `llm_response=`) even though the type
alias is declared positionally, so the parameter names here are load-bearing.

`hypotheses_considered` and `selected_hypothesis` come off the agent's own structured
output, which is why every output schema in this package carries them. They are telemetry,
not authority: nothing deterministic reads them, and a model inflating its own hypothesis
count changes a chart, never a decision.
"""

from __future__ import annotations

from typing import Any

from google.adk.agents import LlmAgent
from google.adk.agents.context import Context
from google.adk.models.llm_response import LlmResponse
from pydantic import BaseModel, Field

from provenance import telemetry

# Session-state keys holding what recall produced (§6.6, item 16). `RECALL_BELIEF_IDS` is what
# the belief store handed over; `RECALL_NOMINATED_IDS` is what the index proposed before the
# store dropped whatever was RETRACTED or UNKNOWN(stale). Both go on every reasoning span, and
# the difference between them is what makes the drop visible rather than merely claimed.
RECALL_BELIEF_IDS = "recall_belief_ids"
RECALL_NOMINATED_IDS = "recall_nominated_ids"


class Diagnosis(BaseModel):
    """What a domain agent hands the Planner. Not an action, and not authority.

    It lives here rather than in a domain file because it is a contract between the domain
    layer and the Planner, not a fact about any one domain: `incident.hand_off` reads these
    five fields by name for whichever agent ran. It was `sre_infra.Diagnosis` until item 21,
    when a second domain would otherwise have had to either copy it -- two schemas one node
    reads identically, which is two schemas that drift -- or import the SRE agent, which makes
    the domain files a dependency chain rather than the peers §5.4's claim is about.
    """

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


def model_name(agent: LlmAgent) -> str:
    """The model string, whether the agent was built with a name or a `BaseLlm` instance."""
    model = agent.model
    return model if isinstance(model, str) else model.model


def attach(
    agent: LlmAgent, *, agent_id: str, agent_version: str, step: str, output_key: str
) -> None:
    """Emit one reasoning-chain span per run of `agent`.

    `live` is keyed by invocation because the Planner can run twice in one incident (§7.1's
    one re-plan). Nodes run in sequence, so an entry is always popped before the next is
    pushed; the key is what makes that a property of the code rather than of the schedule.
    """
    live: dict[str, dict[str, Any]] = {}

    def before(callback_context: Context) -> None:
        recorder = telemetry.reasoning_chain(
            agent_id=agent_id,
            agent_version=agent_version,
            model=model_name(agent),
            step=step,
            recall_belief_ids=callback_context.state.get(RECALL_BELIEF_IDS) or (),
            recall_nominated_ids=callback_context.state.get(RECALL_NOMINATED_IDS) or (),
        )
        live[callback_context.invocation_id] = {
            "cm": recorder,
            "rec": recorder.__enter__(),
            "input_tokens": 0,
            "output_tokens": 0,
            "model_calls": 0,
        }

    def on_response(callback_context: Context, llm_response: LlmResponse) -> None:
        entry = live.get(callback_context.invocation_id)
        if entry is None:
            return
        # Counted before the usage check and not with it (item 32). A response that arrives
        # without `usage_metadata` still cost a request, and the two facts come apart: a
        # count folded into the token guard would under-report exactly the responses whose
        # tokens are already missing, so the A/B's cheapest arm would look cheaper still.
        entry["model_calls"] += 1
        usage = llm_response.usage_metadata
        if usage is None:
            return
        entry["input_tokens"] += usage.prompt_token_count or 0
        entry["output_tokens"] += usage.candidates_token_count or 0

    def after(callback_context: Context) -> None:
        entry = live.pop(callback_context.invocation_id, None)
        if entry is None:
            return
        output = callback_context.state.get(output_key) or {}
        entry["rec"].set_result(
            hypotheses_considered=int(output.get("hypotheses_considered", 0)),
            selected_hypothesis=str(output.get("selected_hypothesis", "")),
            input_tokens=entry["input_tokens"],
            output_tokens=entry["output_tokens"],
            model_calls=entry["model_calls"],
        )
        entry["cm"].__exit__(None, None, None)

    agent.before_agent_callback = before
    agent.after_model_callback = on_response
    agent.after_agent_callback = after
