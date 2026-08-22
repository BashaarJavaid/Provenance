"""The reasoning fleet (item 9) — the first LLM-backed code in the repo.

`ARCHITECTURE.md` §5 assigns three roles to this package: the Orchestrator (§5.3) classifies
a trigger and routes it, a domain agent (§5.4) diagnoses within its domain, and the
Remediation Planner (§5.5) converts a diagnosis into exactly one typed Action.

Every module here builds an ADK `LlmAgent` and returns it; none of them decides anything.
What a model emits is a *recommendation* that the deterministic half then checks:
`action.validate()` overrules a Planner's declared tier, reversibility and blast radius
against the entity model and tool registry, and `risk.score()` reads only the validated
result. §1.1 property 3 -- no LLM-generated number is an input to a deterministic decision --
is preserved by construction rather than by prompt discipline.

Agents are built per incident (`incident.build_graph`), never at import. That keeps the
per-agent tracing state in `_reasoning.py` private to one run, and lets tests substitute a
fake model without touching module globals.
"""
