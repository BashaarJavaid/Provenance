# ADR-007 — ADK Graph Runtime for orchestration; Task API for the park/resume approval path

**Status:** Accepted

**Decision:** The fleet is orchestrated on Google ADK 2.0: the Graph Runtime routes the incident loop (classify → recall → route → propose → verify), and the Task API carries delegation plus the long-running park/resume path — a held action parks the incident until the human approves or denies, then resumes it, minutes or hours later, without the incident living in a process's memory.

**Reasoning, in order of weight:**

1. **Park/resume is a track requirement with a real failure mode (primary reason).** The track asks for asynchronous, long-running operation, and the demo parks an incident on human approval and resumes it on camera. Hand-rolling durable suspension (state serialization, wake conditions, timeout semantics) is exactly the kind of infrastructure that eats a deadline and breaks during a live demo. The Task API is the managed form of the thing; a held incident survives process restarts because it's a task, not a coroutine.
2. **The control loop must own the graph, in code.** Bounded retry ("one re-plan after REFUTED, then escalate") is a property of the *routing graph*, not of any agent's prompt (`ARCHITECTURE.md` §7.1). A declarative graph makes the retry budget and escalation edges visible and testable — no agent owns its own iteration count.
3. **Track alignment with the reference stack.** The brief is built around ADK; the synthetic company extends `google/adk-samples`. Fighting the reference framework spends novelty budget in the wrong place — this project's differentiation is the memory governance, not the orchestrator.

**Boundary discipline still applies:** ADK routes and delegates; it does not authorize. The gateway and the Memory Policy Engine remain the only authorities, and they are plain deterministic code that ADK calls — never the reverse.

**Revisit when:** the Graph Runtime can't express a control-flow requirement cleanly (e.g. the Sweeper's continuous loop may live better as a plain Cloud Run service that merely *emits* into the same trace stream — decide at Phase 9, not before).

**Alternatives considered:** LangGraph (prior art in ProdRescue and well understood, but off-stack for a Google track and would strand the Task API's managed park/resume); hand-rolled asyncio orchestration (full control, but durable suspension is precisely the hard part); Temporal/Cloud Workflows (durable execution without agent-framework integration — a second orchestration layer to reconcile with ADK).
