# ADR-014 — Execution re-checks the signature, and the first Policy Engine is a deliberate stub

**Status:** Accepted (revisit at item 12, when the versioned belief store replaces the stub)

**Decision:** `provenance/executor.py` performs the authorized action and is not a second path
to one: `execute()` re-verifies the `Decision`'s signature against `gateway.public_key_pem()`,
requires an approving outcome, and requires `decision.subject` to name this action's class and
target. It reads `known_good_version` off the entity model and the `rollback_fails` switch off
Firestore at execution time, and emits no span. `provenance/policy.py` is a stub Memory Policy
Engine running the §2.2 stages that item 5 and §4.3 already make free — request-time registry
read, computed confidence, threshold, sign, `create` — and refusing outright to write a second
version of a belief. `provenance/agents/verification.py` judges the pre-declared predicate
against numbers code measured, holds no registry record, and reads nothing itself. The graph
gains `execute` and `resolve`; `resolve` is what opens the `verification.outcome` span, and
`belief.commit` nests inside it. `IncidentOutcome` gains `RESOLVED`.

**Reasoning, in order of weight:**

1. **The gateway is only "architecturally the only path" if the thing at the end of it checks
   (primary reason).** Until item 10 nothing mutated state, so §1.1 property 1 held by there
   being nothing to reach. Now something mutates state, and the property has to survive a
   refactor, a second caller, and a future item that adds a node. The literal reading — the
   `execute` node runs only on the APPROVE branch, so the branch *is* the check — makes the
   guarantee a property of the graph's edge list, which is exactly the kind of thing that gets
   rearranged. So `execute()` re-verifies the signature, the outcome and the subject, and
   `tests/test_executor.py` proves each refusal separately. The cost is three checks per
   execution against a decision the same process just produced; the gain is that the guarantee
   is a property of the function rather than of its call site. The subject check is the one that
   earns its place twice over: `subject` is inside the signature (item 7) precisely so an
   APPROVE for a cheap rollback cannot be presented beside an expensive action, and without a
   consumer that comparison was a claim nothing tested.
2. **The Policy Engine ships as a stub with a hard refusal rather than as a half-engine with a
   soft one.** Item 10 needs one belief committed; items 12–14 own the versioned store, the
   typed-evidence collection, the novelty check and the conflict rule. The tempting middle
   ground is to write v2 when v1 exists and leave the supersession link for later — and that is
   the one option that corrupts data rather than merely lacking a feature, because §3.2's whole
   claim is a supersession chain and history retained forever. Overwriting v1 is worse still.
   So the stub uses Firestore's `create` (atomic, and it loses the race rather than clobbering)
   and answers `REJECT(SUPERSESSION_UNSUPPORTED)`. A refusal is a fact the trace can carry; a
   silently unlinked v2 is a belief nothing can audit. The same reasoning kept `RETRACT` out
   even though the span vocabulary already admits it.
3. **The version deployed comes from the entity model, and that is why §3.1 has eight fields.**
   ADR-011 removed `params` from the Action with this exact moment as the justification: "item
   10's executor reads `known_good_version` off the entity model rather than trusting a
   Planner-supplied version." A `params` field would be a typed channel from a model onto stored
   state, on the one object the whole determinism boundary is a pure function of. The executor is
   where that decision either pays off or quietly gets undone, so `test_the_version_comes_from_
   the_entity_model_not_from_the_action` hands the Planner a predicate naming a *different*
   version and asserts v41 is still what lands.
4. **`resolve` opens the verification span, not the Verification Agent.** `verification.outcome`
   carries `belief_written`, which is not known until the commit has been attempted — so the
   agent cannot be the emitter without either the attribute leaving the shape or the span being
   re-opened afterwards with a wrong duration. Making `resolve` the emitter also gets the nesting
   right for free: `belief.commit` lands inside `verification.outcome`, so the trace reads as
   "this is what was concluded, and this is what memory did about it" rather than as two
   unrelated siblings. It is the same reasoning ADR-013 gave for wrapping the model call in three
   callbacks rather than emitting after it.
5. **A verification agent that fails and a verification agent that hedges land in the same
   place, and the control loop is what puts them there.** §7.3 says an errored or timed-out
   verification is treated as `INCONCLUSIVE`. ADK re-raises a failed node out of the root
   workflow, so the `resolve` node simply never runs — which would leave an *executed* action
   with no verification span at all, reading as an incident nobody checked. So `run_incident`
   catches the failure, and if something executed without being verified it emits the
   `INCONCLUSIVE` span itself. This is §7.1's rule applied to a different counter: no agent owns
   its own failure semantics either.
6. **The fault switch is read at execution time, for ADR-009's third reason.** `rollback_fails`
   is a Firestore document, not deploy config, so a fault is one write and is flippable on
   camera mid-incident. Reading it at boot or caching it would make item 19's `REFUTED` beat
   unrecordable. A failed rollback still *deploys* — the version moves and the rate stays
   spiked — because a rollback that silently skipped its own write would make the refutation a
   fact about the executor rather than about the remediation.
7. **`RESOLVED` is a fifth incident outcome rather than a reuse of `AUTHORIZED`.** After item 10
   an incident that stops at `AUTHORIZED` has *not* finished — it means something executed and
   was never verified, which is precisely the state §7.3 wants distinguishable. It arrives under
   item 2's standing condition: `telemetry.py`, `ARCHITECTURE.md` §8.1 and
   `tests/test_telemetry_schema.py` in one commit. It is not an error status: a resolved incident
   is the only fully successful ending the loop has.
8. **The executor emits no span.** Execution is not a decision — every decision about it was
   made and signed upstream — and §8.1's five shapes each correspond to one decision the
   architecture makes. A sixth shape for "a thing happened" would be the first attribute set
   nothing reads. What execution produced reaches the trace through the verification span that
   judges it, which is the honest place for it.

**What this costs:** one `gemini-3.5-flash` call per incident (~seconds, cents) on top of item
9's three Pro calls. The stub's ephemeral signing key is the same `ponytail:` debt the gateway
carries, with Secret Manager as the named upgrade path and `THREAT_MODEL.md` stating it. The
belief store is one flat `beliefs/{id}` document with the evidence embedded rather than an
`evidence/{id}` collection — item 12 is what normalises it, and doing it now would mean guessing
at a schema whose owner does not exist yet (ADR-010's and ADR-011's rule, applied again).

**Revisit when:** item 12 lands the versioned store (reason 2 disappears entirely, and
`SUPERSESSION_UNSUPPORTED` should become unreachable rather than merely unused), item 19 makes
`REFUTED` write a negative belief (a second `_resolve` branch, not a reshape), item 20 makes
`attempt` exceed 1, or the gateway's signing key moves to Secret Manager (reason 1's re-check
then spans processes, which is the point).

**Alternatives considered:** trusting the `execute` node's position in the graph instead of
re-checking the decision (reason 1); passing the executor the validated `Action` alone and
letting the caller assert approval (same reason — it moves the check to the call site); a
`params` field on the Action carrying `v42->v41` as §4.2's worked example writes it (reason 3);
having the Verification Agent emit its own span and patching `belief_written` in afterwards, or
dropping `belief_written` from the shape (reason 4); letting a failed verification node raise
out of `/trigger` as a 500 (reason 5); reading the fault switches once at process start (reason
6); reusing `AUTHORIZED` as the terminal outcome, or adding `VERIFIED` and `LEARNED` as separate
outcomes (reason 7 — the second splits one ending into two and leaves the UI asking which counts
as done); a sixth `provenance.execution` span shape (reason 8); writing v2 with no supersession
link, or `set()` over v1 (reason 2); a separate `scripts/verify_incident_ten.py` (it would
re-inject the same fault and re-buy item 9's three Pro calls to re-prove a passing line); and
giving the Verification Agent a Firestore tool so it could read the post-state itself — rejected
because an agent that fetches its own evidence can fetch until the evidence agrees with it, and
because the numbers it is shown are then no longer the ones a third party could re-derive from
`verifiable_by`.
