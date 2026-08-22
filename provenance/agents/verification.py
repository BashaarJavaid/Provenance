"""The Verification Agent (§5.8): did the pre-declared predicate hold? (item 10)

§7.2 makes this the honesty gate of the whole memory system: "a memory system that learns
confidently from unreliable verification is worse than one with no memory at all." So the
job is deliberately narrow — read one predicate declared *before* execution, read the
numbers code measured *after* it, and answer with one of three words.

Two constraints keep it honest, and both are structural rather than instructed:

  * **It reads nothing itself.** It is given no tool and no store access. The post-execution
    error rate and config version arrive as session state, put there by `executor.read_state()`
    — a fresh Firestore read, not an echo of what the executor wrote. An agent that could
    fetch its own evidence could fetch until the evidence agreed with it.
  * **INCONCLUSIVE is a first-class answer, not a failure.** §7.2 gives it its own row, and
    §8.1 deliberately keeps it off the error-status list. The control loop treats an exception
    out of this agent as INCONCLUSIVE too (§7.3), so the timid answer and the broken one land
    in the same place: escalate, learn nothing.

Like the Orchestrator, it holds no registry record — it proposes no action and writes no
belief, so §3.4's authority fields would all be empty. Its spans carry `verification-agent@v1`.
Flash rather than Pro because §5.8 says so: high-throughput, lower-stakes.
"""

from __future__ import annotations

from typing import Literal

from google.adk.agents import LlmAgent
from pydantic import BaseModel, Field

from provenance.agents import _reasoning

OUTPUT_KEY = "verification"
STEP = "verification"

AGENT_ID = "verification-agent"
AGENT_VERSION = "v1"


class Verification(BaseModel):
    """§7.2's three-valued outcome. `outcome` is the only field anything acts on."""

    outcome: Literal["CONFIRMED", "REFUTED", "INCONCLUSIVE"] = Field(
        description="CONFIRMED if the predicate plainly held, REFUTED if it plainly did not, "
        "INCONCLUSIVE if the measurements do not settle it."
    )
    hypotheses_considered: int = Field(
        description="How many readings of the predicate were genuinely weighed."
    )
    selected_hypothesis: str = Field(
        description="A short snake_case label for the reading chosen, e.g. predicate_met."
    )


def build(model: str | object, *, agent_id: str, agent_version: str) -> LlmAgent:
    agent = LlmAgent(
        name="verification_agent",
        model=model,  # type: ignore[arg-type]
        description="Judges a pre-declared success predicate against measured post-state.",
        instruction=(
            "You are the Verification Agent of an incident-response fleet.\n"
            "Before the remediation ran, the Planner declared this success predicate:\n"
            "  {success_predicate}\n\n"
            "The remediation has now run on {trigger_target}. These are the values measured "
            "afterwards by code, read fresh from the system of record:\n"
            "  error rate before: {trigger_observed_value}\n"
            "  error rate now: {post_error_rate}\n"
            "  deployed config version now: {post_config_version}\n\n"
            "Answer with exactly one of:\n"
            "  CONFIRMED    -- the measurements plainly satisfy the predicate\n"
            "  REFUTED      -- the measurements plainly contradict it\n"
            "  INCONCLUSIVE -- the measurements do not settle it either way\n\n"
            "Judge only the predicate as written against the numbers given. Do not reason "
            "about whether the remediation was a good idea, and do not substitute a predicate "
            "you would have preferred. If the predicate names a time window the measurements "
            "cannot speak to, that alone does not make the result ambiguous -- the values "
            "above are the post-remediation steady state.\n"
            "INCONCLUSIVE is an honest answer and costs nothing: nothing is learned from it. "
            "Guessing CONFIRMED when the numbers do not support it writes a false belief into "
            "institutional memory, which is the one outcome worse than learning nothing."
        ),
        output_schema=Verification,
        output_key=OUTPUT_KEY,
    )
    _reasoning.attach(
        agent, agent_id=agent_id, agent_version=agent_version, step=STEP, output_key=OUTPUT_KEY
    )
    return agent
