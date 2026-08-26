# ADR-013 — The trigger stream is an HTTP route, and the incident loop is a real graph

**Status:** Accepted (revisit when the Sweeper or a second concurrent incident arrives)

**Decision:** The "live trigger stream" of `ARCHITECTURE.md` §5.3 is `POST /trigger` on the
existing Cloud Run service, guarded by a shared secret. `provenance/incident.py` holds a
frozen `Trigger` dataclass — deliberately **not** a fifth §3 object — and builds ADK's
`google.adk.workflow.Workflow` per incident: `START → orchestrator → recall → route ?→
sre_infra → planner → validate ?→ authorize`, with §7.1's one re-plan as a real edge from
`validate` back to the Planner. `provenance/agents/` holds the three `LlmAgent`s, each with an
`output_schema`, each emitting one `provenance.reasoning.chain` span. A fifth span shape,
`provenance.incident`, is the root everything else nests under. The Planner's private key
arrives as an environment variable. Item 9 stops at the signed decision; nothing executes.

**Reasoning, in order of weight:**

1. **A wake-on-event listener cannot coexist with `min-instances=0`, and the cost ceiling is
   not negotiable (primary reason).** §5.3 says only "wake-on-event against the live trigger
   stream" and names no mechanism. The literal reading is a Firestore snapshot listener on a
   `triggers` collection, and it is the one option the deployment cannot hold: a listener is a
   process that must stay alive, which means an always-warm instance, which `CLAUDE.md`'s cost
   ceiling permits only as "a deliberate, justified exception". Polling has the same problem
   and is not even wake-on-event. An HTTP route is genuinely event-driven, scales to zero
   between incidents, costs nothing idle, and is one `curl` on camera. What is lost is that the
   trigger is *pushed* by whatever noticed the deviation rather than *observed* by the fleet —
   which is how a real monitor works anyway, and is why `scripts/inject_fault.py` writes the
   fault and the trigger is a separate step: the fault is a fact about the world, the trigger is
   something noticing it.
2. **A public endpoint that spends model tokens is a loop somebody else gets to run.**
   `CLAUDE.md` is explicit that "token spend is not the risk; loops are", and the service is
   unauthenticated by design because item 36's cold judge has to reach it. Those two facts
   together make an open `/trigger` an unbounded spend against a fixed $300 credit with
   `max-instances=3` and a budget alert that notifies rather than stops. A shared-secret header
   costs four lines and a README line for the judge. It fails **closed**: an unset token
   returns 403 rather than disabling the check, because the failure mode of the other reading
   is a service deployed without a secret and wide open (§7.3).
3. **The graph is worth building before the branch it exists for, because the branch is
   already here.** ADR-007 chose the Graph Runtime so that "the retry budget and escalation
   edges are visible and testable — no agent owns its own iteration count". Item 20's `REFUTED`
   retry does not exist yet, but §7.1's *malformed* retry does, and `action.outcome_for()` has
   been shipped and callerless since item 6 waiting for this loop. So the re-plan is a real
   edge (`validate → planner`) rather than a `while` in a prompt, and the escalation is a real
   terminal branch. ADK 2.7.1 supports the cycle — checked before committing to it, since a
   graph engine that rejected one would have made this decision differently.
4. **A `Trigger` is not a fifth canonical object, and saying so is the point.** §3 opens with
   "four object shapes carry all authority-relevant data. Don't invent variants", and the
   temptation here is to read that as "so everything must be one of the four". A trigger
   carries *no* authority: every field on it is re-derived from an authority before anything is
   decided — the tier from the entity model, the config versions from the entity model, the
   risk from the table — so a trigger that lied about a tier would not change a single prompt,
   let alone a decision. It is an observation that starts reasoning. It is also not persisted:
   ADR-009's collections do not include one, nothing reads an incident's trigger after the
   incident, and an `incidents` collection would be a schema invented for item 30 four phases
   early. **Item 30 arrived and did not need one**: what a resume acts on is one *held action*,
   not one incident, so the collection is `approvals/` and it is keyed on the decision signature
   ([`ADR-032`](./ADR-032-the-approval-queue.md)). The trigger is still not persisted whole —
   the three fields the resumed leg genuinely needs are copied onto the park, and `raw_content`
   deliberately is not.
5. **The reasoning span had to wrap the model call, which cost three callbacks rather than
   one.** Item 2 defined `provenance.reasoning.chain` and shipped it with no emitter; this is
   its first caller. Emitting it *after* the call is one callback and records a duration of
   zero, which puts a wrong number into the one stream item 32's counterfactual measures. So
   the span opens in `before_agent_callback`, accumulates tokens in `after_model_callback` and
   closes in `after_agent_callback`. `hypotheses_considered` and `selected_hypothesis` come off
   each agent's own structured output, which is why every output schema in the package carries
   them — telemetry, never authority: nothing deterministic reads them, and a model inflating
   its own hypothesis count changes a chart, not a decision.
6. **`output_schema` is how "never free-form text" (§5.5) stops being an instruction.** A
   Planner told to emit JSON is a Planner that can emit prose; a Planner constrained by a
   response schema cannot. It still emits only a *proposal*: `action.validate()` overrules the
   declared tier against the entity model and the declared reversibility and blast radius
   against the tool registry (item 6), so understating any of the three fails validation rather
   than lowering the score. The model's only contribution to the decision is *which* action
   class and target — both then checked against frozen registries. §1.1 property 3 holds
   structurally, not by prompt discipline.
7. **Agents are built per incident, not at import.** The per-invocation tracing state in
   `_reasoning.py`, and a fake model in tests, both want an agent object that belongs to one
   run. Module-level agents would share callback state across concurrent requests on one Cloud
   Run instance. Constructing three pydantic models per incident costs nothing next to three
   model calls.
8. **The Orchestrator gets no registry record.** §3.4's record exists to carry authority — tool
   scope, memory domains, standing, a public key to verify a signature against — and the
   Orchestrator has none of it: it proposes no action and writes no belief. Registering it
   would mean a fourth keypair that signs nothing and a record whose every authority field is
   empty, which makes the registry mean less rather than more. Its span's `agent.id` answers
   who reasoned, which is a different question from who may act.
9. **The Planner's private key is an environment variable, marked as a shortcut.**
   `seed_registry.py` prints each private half once and stores it nowhere (ADR-010), so
   something outside the repo has to carry it. Secret Manager is the named upgrade path and the
   shape of `load_planner_key()` does not change when it happens; item 7 took the same posture
   for the gateway's own ephemeral signing key, and `THREAT_MODEL.md` says so rather than
   letting the deployment imply otherwise. A multi-line PEM is why `deploy.sh` passes an
   `--env-vars-file` (created 600, removed on every exit path) rather than `--set-env-vars`.

**What this deliberately does not do:** execute the approved action or verify it (item 10 —
these nodes are appended, not reshaped), persist an incident, park or resume a held one (item 30
ships both: a HOLD writes an `approvals/{id}` record and still ends the incident with
`outcome=HELD`, and `incident.resume()` is the other half — [`ADR-032`](./ADR-032-the-approval-queue.md)), recall anything
(recall returned empty until item 16, which filled it in `provenance/recall.py` without reshaping the graph — the step exists so item 18 fills a slot
rather than reshaping a graph), render anything (item 11 owns all six §8.2 surfaces), or
implement item 20's `REFUTED` retry budget — **since built, in
[`ADR-023`](./ADR-023-the-bounded-retry.md), as one more conditional edge on this same graph and
nothing else structural, which is the clearest evidence available that reason 3 chose the right
runtime.**

**Revisit when:** a second incident can run concurrently (the per-incident graph is already
safe; what is not yet is the single `InMemorySessionService` per run being thrown away, which
item 30's park/resume replaces with a durable one), or the Sweeper arrives in Phase 9 — ADR-007
already flags that a continuous loop may live better as a plain service that merely emits into
the same trace stream.

**Alternatives considered:** a Firestore snapshot listener or a polling loop for the trigger
(reason 1); leaving `/trigger` open, or rate-limiting it instead of authenticating it (reason 2
— a scripted loop still spends serially); `SequentialAgent` or a plain async `for` loop instead
of the Graph Runtime (reason 3 — both would be replaced wholesale at item 20, and a plain loop
would need an ADR amending ADR-007); a `Trigger` persisted to a `triggers` collection, or
declared as a fifth §3 object (reason 4); emitting the reasoning span after the call for one
callback instead of three (reason 5); prompting for JSON instead of constraining with
`output_schema` (reason 6); module-level agent singletons (reason 7); registering the
Orchestrator as a fourth agent, or reusing the routed-to agent's identity on its span (reason 8
— the second would attribute the routing decision to the agent that was routed *to*, corrupting
item 28's panel and item 32's per-agent counts); Secret Manager for the Planner key now (reason
9); a fixed registry of predicate templates instead of a free-text `success_predicate` hashed
into a `predicate_id` (it would make verification deterministic and thereby leave §5.8's
Verification Agent with nothing to reason about and item 19's `INCONCLUSIVE` path with no
reason to exist).
