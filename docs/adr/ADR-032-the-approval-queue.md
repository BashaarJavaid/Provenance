# ADR-032 — The approval queue is a Firestore record and a second gateway door: ADK 2.7.1 has no Task API, so item 30 builds the park it needs and says so

**Status:** Accepted

**Decision:** A held action parks as a document in a new `approvals/{id}` collection
(`provenance/approvals.py`), written by `incident.py`'s `authorize` node on a `HOLD`. A human
answers it through `POST /approvals/{id}`, which calls `incident.resume()` — a **second public
coroutine** beside `run_incident()` — which calls **`gateway.resolve()`**, a **second public
door** beside `authorize()`. `resolve()` trusts nothing the queue stored: it re-runs
`action.validate()` over the parked proposal, re-reads the registry, recomputes §4.2, and signs
a fresh `Decision` at a new `stage="human"` with reason `HUMAN_APPROVED` or `HUMAN_DENIED`. Both
verdicts are written to the existing `authorizations/` ledger, which gains an `approver` field.
An approved resume executes, verifies and learns through the same functions the first leg would
have. Nothing expires.

**ADR-007's Task API does not exist in the installed ADK, and this ADR is where that is
recorded rather than papered over.**

**Reasoning, in order of weight:**

1. **There is no Task API, and the nearest primitives cannot survive `--min-instances=0`
   (primary reason).** ADR-007 chose "the Task API carries delegation plus the long-running
   park/resume path — a held incident survives process restarts because it's a task, not a
   coroutine." `google-adk==2.7.1` has no such API. What it has is `Runner.run_async(
   invocation_id=…)`, an `App(resumability_config=ResumabilityConfig(is_resumable=True))` flag,
   and a pluggable `SessionService` — assembled, not managed. Making that durable needs a
   session backend, and both available ones fail here for different reasons:
   `SqliteSessionService` writes to the container filesystem, which Cloud Run discards on
   scale-to-zero — precisely the event a five-minute park is guaranteed to meet at
   `--min-instances=0`; and `VertexAiSessionService` needs an Agent Engine, which is a paid
   resource that **bills while idle**, the one category the cost ceiling names as able to drain
   the credit. Reason 1 of ADR-007 was that hand-rolling durable suspension "eats a deadline and
   breaks during a live demo"; that reason survives, and it now argues for a Firestore document
   rather than against one. The store is already there, already the single source of truth
   (ADR-001), already survives everything, and adds no paid resource.

2. **The `_Scratch` boundary would have to be broken to use sessions at all.** `_Scratch`'s
   docstring states the rule: session state holds "only what an agent's instruction interpolates
   — strings and numbers", because "round-tripping [a `Decision` and an `Action`] through JSON
   would mean the object the caller inspects is not the object the gateway signed." ADK
   resumption restores from session state. So the ADK-native path requires putting exactly the
   two objects that rule excludes into exactly the place it excludes them from. What the
   `approvals/` document stores instead is the **raw proposal dict** — an *input* to the
   pipeline, re-validated at resume, never a conclusion — which does not break the rule because
   it never claims to be a signed object at all.

3. **The gateway's key is per-process, so a park cannot be verified — and must not need to be.**
   `gateway._signing_key()` carries a `ponytail:` comment saying signatures "do not survive a
   Cloud Run restart", with Secret Manager as the named upgrade path. A five-minute park at
   `--min-instances=0` crosses that boundary by design, so the stored `held_signature` is
   uncheckable by whichever process answers. Three options: persist the key, trust the record,
   or **recompute**. Persisting the key adds a third deploy secret, a Secret Manager dependency
   and a local/CI fallback, to make one document verifiable. Trusting it puts the score a human
   is shown, and the action that then executes, on a Firestore document nothing checked.
   Recomputing is what the rest of the system already does everywhere: `authorize()` takes
   `object` rather than a validated `Action` for this same reason, and §4.1 forbids a
   deterministic decision consuming a number it did not compute. **Tampering with a parked
   proposal therefore changes its outcome deterministically instead of slipping past a check** —
   and it is stronger than expected: understating a tier or a blast radius does not reach the
   risk table at all, because §3.1 checks those three fields against an authority that is not
   the proposal, so the lie is a `DENY/schema/SCHEMA_INVALID`. Item 11's validation is still
   standing between a stored document and an execution days after the process that stored it
   died. `tests/test_gateway.py::test_a_tampered_proposal_dies_at_schema_rather_than_being_waved_through`.

4. **A second gateway door, because re-running the first one would hold the action again.**
   §4.2 is a lookup, and nothing about it changes when a person says yes: `authorize()` on an
   approved proposal returns `HOLD` forever. The human's authority has to enter the pipeline
   somewhere, and §1.1 property 1 says the somewhere is the gateway or the property is false.
   Two alternatives were rejected. A **countersignature** — the HELD decision stands and
   `executor.execute()` requires a second signature from `approvals.py` — moves property 1 from
   the gateway to the executor, so "the gateway is architecturally the only path" would become a
   statement about two modules agreeing. A **human credential** — mint one and re-run
   `authorize()` with the risk band bypassed for it — keeps one door at the price of putting a
   bypass inside the one stage ADR-003 says has no exceptions. `resolve()` is the shape item 29
   already set when `expire()` joined `commit()` and `retract()`: one authority, one module,
   more than one question it can be asked. `tests/test_gateway.py` pins the count at two, and
   `CLAUDE.md`'s standing order was amended in the same commit rather than quietly outgrown.

5. **`resolve()` re-reads the registry, and that is not belt-and-braces.** §1.1 property 4 is
   "the registry is read at request time, not at boot", and a resume *is* a request — separated
   from the proposal by however long a human took. A park is exactly the window in which
   standing can move. So a `SUSPENDED` agent's action is denied regardless of the verdict: a
   human may not approve for an agent the fleet has stopped trusting, which is what makes
   standing losable rather than advisory. `DEGRADED` deliberately does **not** block a resume —
   it is what *caused* item 28's hold, and blocking on it would make that queue entry
   unanswerable. One check has no §2.1 precedent and is here on §7.3's default posture: an agent
   **rotated** during the park (`agent_version != agent.version`) denies at `identity`, mirroring
   `authorize()`'s own version check. `--rotate` is a human act, and an action proposed by a
   version that no longer exists was proposed by somebody the fleet no longer is.

6. **The approver is a bounded identifier and there is no `humans/` collection.** §8.1 admits
   "identifiers, hashes, enums and numbers — never content", so `approvals.check_approver()`
   validates at the HTTP boundary rather than at the exporter. An **allowlist** of permitted
   approvers was rejected: §9 names Dana Ruiz as a persona, nothing in the design reads a human
   record, and a roster of who may approve is an authorization decision *about people* that no
   document in this repo makes — inventing one here is the speculative plumbing `CLAUDE.md` §2
   rules out. `THREAT_MODEL.md` already discloses that the model "does not defend against a
   malicious approver"; that disclosure is what this reason rests on, and it is unchanged.

7. **The resume lives in `incident.py` and runs the tail as a two-node graph.** `_resolve()` and
   the commit path are private, and exporting them so `approvals.py` could call them would make
   `incident.py`'s internals a public surface to keep the resume in one file. Rebuilding the
   full five-node graph with `START` wired to `execute` was the other candidate: it would need a
   second graph builder whose only job is skipping five nodes, plus a rehydrated `_Scratch` to
   feed it. What ships is `executor.execute()` called directly — nothing routes, an approved
   action has one path left — and then the **real Verification Agent** through a real `Runner`
   on a two-node graph, so the resumed leg emits the same `reasoning.chain` span the first leg
   would have. Item 20's re-plan edge is deliberately absent: a re-plan needs the Planner, and
   the Planner's proposal is what the human answered, so a `REFUTED` resume escalates.

8. **A new root span with the same `incident_id`, not the parked trace.** Reconstructing the
   parked trace context would read beautifully in Cloud Trace and would be invisible on the
   demo screen: ADR-015's span buffer is in-process, so after a scale-to-zero a resumed leg
   attached to a dead trace renders as a fragment with no parent. An OTel `Link` was the third
   option and would put a new mechanism into §8.1's closed attribute sets for one call site. The
   parked `trace_id` is stored on the record as the pointer back, and the two legs join on
   `incident_id` — which the incident span already carries.

9. **`stage="human"` is a word, not a fifth shape.** Item 29's `EXPIRE` precedent: a human's
   verdict is the same stage-6 decision the other five stages produce — signed, reported, with
   the same arithmetic riding along — so a separate span shape would make item 31's card and the
   ledger panel read two streams for one decision. `_ERROR_OUTCOMES` needed no change at all: it
   keys off the outcome, so a human denial is `DENY` and is already an error, while an approval
   is not. Added under item 2's standing condition — module, `ARCHITECTURE.md` §8.1 and
   `tests/test_telemetry_schema.py` in one commit.

10. **The ledger widens, and ADR-019 §9's exclusion turns out to be about something else.**
    §9 says "a HELD action parked on a human and a DENIED one never happened; neither rests on a
    belief in the way that needs reviewing." That is right about an *agent-stage* denial, which
    nobody was asked about, and about an action still parked. A **human's** verdict is the
    opposite case: somebody was asked, and answered. The item's own line — "denial is signed into
    the ledger" — asks for exactly that, and `authorizations/` is what the word "ledger" means in
    this repo and what §8.2's panel already renders. So `approver` joins the record, optional on
    read so every row written in the fifteen items before this one still parses. The alternative
    — a signed resolution living only in `approvals/` — preserves ADR-019 verbatim and makes
    "the ledger" point at a collection that has never been called one.

11. **The park cites the beliefs the fleet reasoned from, not the ones memory holds at resume.**
    §6.4's retraction join has to survive a park, and recall runs once, at trigger time. Re-running
    it at resume would cite whatever memory says days later, which is a different claim than "what
    this action rested on". `entity_ids` only, for §6.2's reason, and `recall.Recalled` is what
    keeps that a property of a type. `domain`, `routed_to` and the three trigger facts are stored
    on the same principle: the resumed belief's domain and `committed_by` are facts about what the
    fleet did, and `incident.DOMAINS` is keyed on a classification the Orchestrator made once.

12. **Nothing expires, and the absence is checked.** §7.3's row is "human approver unavailable →
    held actions stay parked; nothing auto-approves on timeout", and the item repeats it. An
    expiry to `ESCALATED` — still fail-closed, still never approving — was considered and
    rejected: it invents a duration no document specifies and adds the branch §7.3 says should
    not exist. Because the rule is an absence, it is tested as one:
    `test_nothing_in_this_module_consults_a_clock` asserts the module contains no wall-clock read
    and no timestamp comparison, so an expiry is impossible rather than merely unwritten.

13. **A verdict is given exactly once.** `approvals.resolve()` runs `PARKED → APPROVED | DENIED`
    and refuses anything already answered, re-reading the record itself rather than trusting one
    the caller found — `policy.expire()`'s move, and for the same reason: the read and the write
    are two moments. Without it a replayed `POST` executes the action a second time. The route
    renders that refusal as `409`, so a retry reads as the no-op it is.

14. **Routes only; the card is item 31.** ADR-008 and ADR-015 both deferred "still no framework"
    to "item 30's approval queue — the first surface that genuinely *writes*". It writes, and it
    writes over `fetch`: two routes, no client-side write state, because `provenance/web/index.html`
    is untouched and its Approval-card placeholder still names item 31. **The revisit therefore
    re-defers to item 31**, which is where the approve button and its optimistic-update question
    actually live. `GET /approvals` is unauthenticated for the reason the other three reads are
    (item 36's cold judge, and a read spends nothing); `POST` reuses `/trigger`'s guard and its
    secret, because a resume runs the Verification Agent and so spends model tokens against the
    same fixed credit — which is the entire argument that guarded `/trigger`. A second secret
    would be a second thing that can be missing on Oct 1, and it fails closed when unset.

**Boundary discipline still applies:** the queue decides nothing. `approvals.py` is a record,
`incident.resume()` is a loop, and `gateway.resolve()` is the authority — the same split
`sweeper.py` and `policy.expire()` took one item ago. No LLM-produced number enters any of it;
the only model call on the whole resumed path is the Verification Agent, on the approve branch,
judging a predicate declared before anything executed.

**Revisit when:** item 31's card gives the queue a real surface, at which point ADR-015's
framework question is genuinely due; a second incident can park concurrently, at which point
`pending()`'s single-field query wants an ordering index rather than a sort in Python; ADK ships
a Task API that is durable without a paid session backend, at which point reason 1 is worth
re-reading rather than assumed; a park needs to outlive a *key* rotation as well as a process,
at which point reason 3's Secret Manager path is what to take; or a human approver ever needs to
be authenticated as themselves rather than as the holder of the deploy token, at which point
reason 6's allowlist and `THREAT_MODEL.md`'s disclosure both reopen together.

**Alternatives considered:** ADK `ResumabilityConfig` + `SqliteSessionService` (dies with the
instance) or `VertexAiSessionService` (paid, bills while idle) — reason 1; a Firestore park
resumed *through* the ADK graph, paying both the JSON round-trip and a session backend — reasons
1 and 2; persisting the gateway signing key in Secret Manager, or trusting the stored record
unverified — reason 3; a countersignature checked by `executor.execute()`, or a minted human
credential re-entering `authorize()` with the risk band bypassed — reason 4; an allowlist of
permitted approvers, or no approver field at all — reason 6; `approvals.resume()` with
`incident.py`'s helpers made public, or a second full graph builder — reason 7; reconstructing
the parked trace context, or an OTel `Link` — reason 8; a fifth `provenance.approval.resolution`
span shape, or no span for the resume at all — reason 9; a signed resolution living only in
`approvals/`, leaving `authorizations/` approvals-only — reason 10; re-running recall at resume
— reason 11; a park expiring to `ESCALATED`, or carrying a visible age field — reason 12; a
minimal queue list or the full card in `index.html` — reason 14; a separate
`PROVENANCE_APPROVAL_TOKEN`, or an unauthenticated `POST` — reason 14.
