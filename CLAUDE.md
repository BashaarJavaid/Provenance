# CLAUDE.md

Project-specific context and instructions for Provenance, merged with a set of general behavioral guidelines (sections 1-4 below, adapted from [andrej-karpathy-skills/CLAUDE.md](https://github.com/multica-ai/andrej-karpathy-skills/blob/main/CLAUDE.md)) aimed at reducing common LLM coding mistakes: unstated assumptions, speculative complexity, unrelated edits, and vague success criteria.

**Tradeoff:** these guidelines bias toward caution over speed. For trivial tasks, use judgment. This file is standing orders, not a changelog: what shipped lives in `ROADMAP.md`'s `— **done**:` notes; why it looks that way lives in `docs/adr/`. Update this file only when a new standing order or live trap appears.

---

## Project

Provenance — a fleet of agents that detects, diagnoses, fixes, and verifies enterprise incidents, and writes what it confirmed into a governed institutional memory. The claim: **an LLM never decides what the organization does, and never decides what the organization believes.** Full pitch in `README.md`. Hackathon deadline: **August 31, 2026, 5:00 PM PDT** (All Things Agentic Hackathon, Fortified Enterprise Fleet track).

## Where things live

- `README.md` — what this is, the architecture diagram, tech stack, pre-existing-code disclosure. Read this first.
- `ARCHITECTURE.md` — both decision pipelines, canonical typed objects, the determinism boundary, memory design, failure modes, observability, testing strategy, deployment. Load this when working on the gateway, the Memory Policy Engine, or any core loop logic.
- `THREAT_MODEL.md` — what's protected against, what isn't, and the assumptions the design rests on. Load this when working on anything security-relevant (gateway, risk table, memory writes, sanitizer, standing).
- `docs/adr/` — one file per architecture decision, including why several common alternatives weren't chosen. Load the specific ADR relevant to the component being touched, not all of them by default.
- `docs/generality-report.md` — spec §18's generality claim as a measured number: what the second domain cost, itemized, and the ≈10-line prediction a third domain has to beat. Load this before touching `incident.DOMAINS`, `policy.HALF_LIFE_DAYS` or anything that claims the control plane is domain-agnostic.
- `ROADMAP.md` — the fourteen-phase build order as a living checklist. At session start, read the top paragraph and the **open** item. Completed items' `— **done**:` notes are the changelog — load one when touching that component, not all of them. Update ROADMAP as items complete.
- `docs/demo-script.md` — the 3:40 demo choreography, beat by beat (spec §13, extracted). Load for demo/rehearsal work (items 37–38).
- `docs/submission.md` — track requirements, judging weights, bonus points, submission logistics (spec §4 and §21, extracted). Load for items 33–36 and 38.
- `self-healing-enterprise-project-spec (1).md` — **frozen historical artifact**, superseded by the files above and stale on model names (it says "Gemini 3.5 Pro"). Its header maps every section to its current home. Don't edit it; don't cite it as current.

Don't load `ARCHITECTURE.md`, `THREAT_MODEL.md`, or the ADRs in full for unrelated tasks (e.g. a pure UI tweak or demo-recording step) — pull in only the file relevant to the current task.

## Where new information goes

**One fact, one home, everywhere else links.** The doc set was audited on Aug 25 and about half of it was the same content written three times — every shipped item narrated once in its ADR, again in an `ARCHITECTURE.md` "As built" block, and again in its `ROADMAP.md` done-note. That is the failure mode this section exists to prevent. It is the operational form of the rule at the top of this file: standing orders here, what shipped in `ROADMAP.md`, why it looks that way in `docs/adr/`.

| What you have to write down | Its one home | Everywhere else |
|---|---|---|
| A decision, and the alternatives you rejected | the item's `docs/adr/ADR-0NN` | link to it — never restate the reasoning |
| What the design *is* — a rule, an object shape, a pipeline stage | `ARCHITECTURE.md` §N | the ADR's **Decision** paragraph may summarize it; nothing else may |
| What shipped, what ran live, what deviated | the ROADMAP item's `— **done**:` note | link by item number |
| A threat, a disclosed limit, an assumption the design rests on | `THREAT_MODEL.md` | link — don't re-derive the mechanism, point at §N or the ADR |
| A measured number and the method behind it | its own `docs/*-report.md` | cite the headline sentence + link; never copy the table |
| A standing order, or a trap that would strand the fleet | this file | — |
| Demo choreography / submission logistics | `docs/demo-script.md` / `docs/submission.md` | — |

Rules that follow from it:

- **Grep before you write a paragraph.** Pick a distinctive phrase from what you're about to say and search the corpus. If it's already written, link instead. This is thirty seconds and it is the whole discipline.
- **An `ARCHITECTURE.md` "As built" block carries three things only:** the module path, the constant names and their values (these often live nowhere else — `CREDENTIAL_TTL_SECONDS = 300`, `CLASS_MARGIN = 0.05`, `SIMILARITY_FLOOR = 0.55`), and any place the implementation **corrects** the design text above it. Reasoning goes to the ADR; live evidence goes to the ROADMAP item.
- **A ROADMAP done-note carries what the ADR cannot:** what shipped, live evidence (trace ids, read-backs, what was asserted), mutation-check results, findings discovered by running it, deviations from the item's own text, registry/state changes, and cost. Design reasoning belongs in the ADR — write it there and point at it.
- **Never restate a frozen number.** `1+1+0+0 = 2` and `4+2+2+3 = 11`, `SUP-042`'s 0.575 → 0.770, §4.3's base weights, the generality figures — each has one home. Cite the section; copying the number is how the docs come to disagree with themselves.
- **Conventions that apply to every item** go once in `ROADMAP.md`'s "Conventions these notes assume" block at the top of the Build Order — not repeated per item.
- **The spec is frozen.** Never add to `self-healing-enterprise-project-spec (1).md`, and don't cite it as current; its header maps each section to the document that superseded it.
- **Check the insertion point when appending to a ROADMAP item.** Two blocks were found in the wrong item during the Aug 25 audit (item 11's trace-UI findings sat in item 6, and item 19's mutation record overwrote item 13's). Both were single bad offsets in an otherwise clean commit. Read the item number above *and* below the line you're adding.

## Conventions

The four load-bearing properties from `ARCHITECTURE.md` §1.1 are hard rules, not guidelines — a change that violates one is wrong no matter how convenient:

- **No direct path from any reasoning agent to a state-mutating action.** The gateway is the only path. Don't add a second one "for testing" that could ship. `gateway.authorize()` is the module's only public coroutine; it takes `object`, not `Action`, and every terminal outcome is a returned `Decision`.
- **The memory write path mirrors the action path.** Probabilistic recommends, deterministic decides — for beliefs as for actions. The Memory Analyst never commits; the Policy Engine never reasons. Don't add an Analyst node to the incident graph; it runs from a seeder.
- **No LLM-generated number is an input to a deterministic decision.** Confidence comes from the published noisy-OR formula (`ARCHITECTURE.md` §4.3); risk comes from the lookup table (§4.2). If a change makes a model-asserted number decisive anywhere, it has crossed the determinism boundary — reject it.
- **The registry is read at request time, not at boot.** Don't cache standing. `get_agent()` reads Firestore on every call.

Further conventions:

- Python 3.12, Google ADK 2.0, GCP (Cloud Run, Firestore, Vertex AI). Async throughout. No `localStorage`/browser-storage patterns in the backend. Package is **`provenance/`**, never `services/` (that name would shadow installed `portunusmcp`).
- Agents emit **typed objects only**: the Planner emits the canonical typed Action (`ARCHITECTURE.md` §3.1), never free-form text; the Analyst emits typed evidence and recommendations. Don't invent new response shapes — reuse the four canonical objects in §3. There is no `params` field and no `raw_content` field; don't add either.
- Verification is three-valued (`CONFIRMED` / `REFUTED` / `INCONCLUSIVE`) and memory learns **only** from the outcomes verification could *settle*: `CONFIRMED` commits what worked, `REFUTED` commits the negative belief (confirmed refutation is knowledge — §7.2), and `INCONCLUSIVE` writes **nothing**. Never write a belief on `INCONCLUSIVE` — no partial credit. In `incident.py` the rule is the shape of `_LEARNS_FROM` rather than a branch: `INCONCLUSIVE` has no entry, so committing on it means adding a key.
- Class beliefs are **advisory only**, and since item 23 that is two mechanisms rather than a rule to remember: `recall.Recalled` keeps them out of `entity_ids`, which is what `authorizations/{id}` cites, and `policy.commit()` refuses `CLASS_BELIEF_NOT_EVIDENCE` when a proposal cites one as evidence. They may reorder hypotheses; they may never authorize an action or serve as evidence for an entity-belief commit. The ledger cites `entity_ids`, never `belief_ids`.
- Beliefs are append-only: supersession and retraction, never overwrite, never delete. Nothing under `provenance/` modifies or deletes a version. Don't add a `current_version` pointer; `current()` walks `versions/1, 2, …`.
- Fail-closed is the default posture for any subsystem failure that would silently weaken a guarantee (`ARCHITECTURE.md` §7.3). If unsure whether something should fail open or closed, it's closed.
- No ML/LLM-based risk scoring — a deliberate constraint (see `docs/adr/ADR-003`), not a gap to fill in later. `risk.BASE` is the only home of `base[action_class]`; a third tool cannot ship without a base score. Don't add a third supplier tool to reach execution — the supply-chain incident ending `HELD` at 11 is the design.
- PortunusMCP is a library dependency only; all track-facing authorization logic is new code here and must stay visibly so in the commit history (disclosure table in `README.md`, reasoning in `ADR-004`). It installs as a separate `--no-deps` step and **must never go in `pyproject.toml`**. CI must not gate on `pip check`. The Dockerfile's two-step install must stay two steps in that order.
- Emit spans only through `provenance/telemetry.py` helpers. Don't call the OTel tracer directly, and don't invent a new span shape or a content-bearing attribute key without changing `ARCHITECTURE.md` §8.1 and `tests/test_telemetry_schema.py` together. Attributes carry identifiers, hashes, enums and numbers — never content.
- `/health`, never `/healthz` (Cloud Run swallows the latter). Don't rename an `<h2>` in `provenance/web/index.html`. `POST /trigger` is token-guarded and **fails closed when `PROVENANCE_TRIGGER_TOKEN` is unset** — don't remove the guard. `GET /trace` and `GET /belief/{entity}` are unauthenticated on purpose.
- Deploy at `--max-instances=1` (the trace UI's span buffer is in-process) and `--min-instances=0`. Don't raise either for convenience.
- No entity document carries a `status` / `confidence` / `belief` field — `SUP-042` is AT_RISK through the belief store, never as a seeded field. `inventory-api` is tier2 and `SUP-042` is tier1 (the only route to the frozen scores 2 and 11); `pricing-api` has no config history on purpose.
- Reasoning roles run on `gemini-2.5-pro`; verification on `gemini-3.5-flash`; the item-26 sanitizer on `gemma-4-26b-a4b-it-maas`. Gemini 3.5 Pro is not served to this project. Gemini 3.x lives on the **`global`** endpoint.
- Don't lower Model Armor from `HIGH` if the crafted payload starts matching — re-script item 27 instead.

## Commands

Cheat sheet. Assertions, mutation posture, and Gemini cost live on the named ROADMAP item's `verify:` / `done` line. Live scripts need credentials and are not in CI. Incident scripts also need `PROVENANCE_PLANNER_KEY`, `GOOGLE_GENAI_USE_VERTEXAI=1`, and `GOOGLE_CLOUD_LOCATION=global`. Default project: `provenance-hackathon`.

**Local**

- Setup: `python3.12 -m venv .venv && .venv/bin/pip install -e ".[dev]" && .venv/bin/pip install --no-deps portunusmcp==0.1.0` — second step is mandatory (item 0.5). `pip check` exits non-zero by design.
- `.venv/bin/pytest` / `.venv/bin/ruff check .` / `.venv/bin/ruff format --check .` / `.venv/bin/mypy provenance/`
- CI (`.github/workflows/ci.yml`): lint, format, type-check, tests — no cloud credentials, no `pip check`

**Setup / deploy**

- `./scripts/set_budget.sh` — $300 budget, 50/90/100% alerts; already run
- `./scripts/gcp_setup.sh` — project, APIs, IAM, Firestore, Gemini probe; idempotent. `PROJECT_ID` / `REGION` override defaults
- `./scripts/deploy.sh` — requires `PROVENANCE_PLANNER_KEY` and `PROVENANCE_TRIGGER_TOKEN`; `--max-instances=1`. Live: https://provenance-808273007560.us-central1.run.app
- HTTP: `GET /health`, `GET /`, `GET /trace`, `GET /belief/{entity}`; `POST /trigger` (token)

**Seed** (credentials)

- `scripts/seed_firestore.py` — item 4; create-if-absent; `--reset` restores baseline
- `scripts/seed_registry.py` — item 5; **no `--reset`**; `--rotate <agent-id>` is the key path
- `scripts/seed_belief.py` — item 17; **no `--reset`**; writes `SUP-042` AT_RISK
- `scripts/seed_class_belief.py` — item 23; **no `--reset`**
- `scripts/setup_model_armor.py` — item 25; **no `--reset`**
- `scripts/inject_fault.py` — `--clear` / `--rollback-fails` / `--ambiguous` / `--target` (default `inventory-api`)

**Verify** (credentials unless noted)

- `scripts/emit_trace_samples.py` — item 2
- `scripts/verify_registry.py` — item 5
- `scripts/verify_gateway.py` — item 7; mutates nothing
- `scripts/verify_denial_by_registry.py` — item 8; writes standing, restores
- `scripts/verify_incident_one.py` — items 9–11.5 + 18; `--runs N`; `--remember` is item 18
- `scripts/verify_belief_store.py` — items 12–15; writes including the registry; needs `sre-infra-agent` `GOOD` with an empty window
- `scripts/verify_recall.py` — item 16
- `scripts/verify_belief_inspector.py` — item 17; HTTP only, no cloud credentials of its own
- `scripts/verify_refuted.py` — items 19–20; `--refuted` / `--inconclusive`; imports teardown from `verify_incident_one.py`
- `scripts/verify_supply_chain.py` — item 21; mutates nothing
- `scripts/verify_class_belief.py` — item 23
- `scripts/verify_incident_three.py` — item 24; `--runs N`
- `scripts/verify_model_armor.py` — item 25; mutates nothing
- `scripts/verify_sanitizer.py` — item 26; mutates nothing
- `scripts/verify_injection_arc.py` — item 27; mutates nothing; run `verify_supply_chain.py` alongside it — same trigger without the payload, same 11

Still to come: `--memory-disabled` counterfactual A/B runner (item 32).

## Cost ceiling

The GCP project runs on a **$300 free-trial credit and must not exceed it**, and the hosted demo has to stay alive through **October 1** judging. Trial credit also expires ~90 days after activation, so unspent credit is not banked. Treat the ceiling as a design constraint, not something to audit afterwards — billing data lags up to a day, so by the time a number looks wrong the money is already gone.

- **Before adding any paid resource** — a deployed model endpoint, a Cloud Run service with `min-instances > 0`, a scheduled job, anything with a GPU — state what it costs per hour and whether it bills **while idle**. Idle-billing resources are the only things that can realistically drain the credit.
- **The Gemma 4 sanitizer was the single largest risk, and item 26 removed it rather than managing it.** A dedicated Vertex endpoint bills by the hour whether or not it serves a request — order $1–4/hr, the entire credit in under two weeks. `gemma-4-26b-a4b-it-maas` is served **as a service** and bills per token, so there is nothing to deploy, nothing to undeploy and nothing that can be left running overnight (`docs/adr/ADR-028` §1). **The rule the old one stood for still holds:** if a future beat needs a dedicated endpoint, it is deployed only while being built or recorded, and undeployed immediately after.
- **Cloud Run stays `min-instances=0`** with a low `max-instances`. Scale-to-zero is the default posture; an always-warm instance is a deliberate, justified exception, not a convenience.
- **Token spend is not the risk; loops are.** A Gemini call costs cents; an agent looping on one costs whatever it can reach. The bounded retry (Phase 5, item 20) and the escalation path are cost controls as much as correctness ones.
- **The backstop is a budget, not a habit.** `scripts/set_budget.sh` configures a $300 Cloud Billing budget with alerts at 50/90/100%. Alerts notify, they do not stop spend — the four rules above are the actual guardrail.

## Current phase

Phases 1–7 done; Phase 8 under way. Items 0.5–27 shipped (Aug 25). **Item 28 (the poisoning arc + standing) is next.** See `ROADMAP.md` for the checklist and done notes; load the ADR for the component you touch.

Live traps (would strand the fleet or the demo):

- `seed_registry.py`, `seed_belief.py`, `seed_class_belief.py`, and `setup_model_armor.py` have **no `--reset`**. Don't invent one. A re-run must never rewrite a stored `DEGRADED`, a poisoned-then-defended `SUP-042` chain, the class belief, or a Model Armor template item 27 may tune on camera.
- `SUP-042`'s chain and `belief-service.tier2` are permanent demo state; item 28 attacks the first (item 27 ran against it and left it byte-identical). The class name is the Analyst's — read it out of the store, don't hardcode it. `pricing-api` must stay belief-free.
- `remediation-planner` is at **`v3`**. Read `agent.version` off the record, never hardcode it. Private keys are printed once by `--rotate` and stored nowhere — `PROVENANCE_PLANNER_KEY` is the env var.
- `scripts/verify_belief_store.py` refuses unless `sre-infra-agent` starts `GOOD` with an empty rejection window. Clearing that window is a human act; the script's teardown writes `rejection_window: []`.
- `scripts/verify_refuted.py` imports its teardown from `verify_incident_one.py` — two restore paths over one fixture drift. Don't duplicate it.
- The sanitizer runs on **`gemma-4-26b-a4b-it-maas`**, served **only** from the `global` endpoint, and it `429`s on roughly half of all calls — that is `PUBLIC_PREVIEW` shared capacity, not a defect. `sanitizer.SANITIZE_ATTEMPTS` is the answer; re-run rather than raising it. Nothing is deployed and nothing bills while idle, so there is no undeploy step (this replaces the old "Gemma bills while idle" trap — `ADR-028` §1 records why it is gone).
- The sanitizer's `PLACEHOLDER` check is not tidiness: Gemma has been observed listing the PII it replaced in `pii_tokens`. A token that is not a placeholder **is** PII. Don't relax it to a prompt instruction.

---

## 1. Think Before Coding

**Don't assume. Don't hide confusion. Surface tradeoffs.**

Before implementing:
- State your assumptions explicitly. If uncertain, ask.
- If multiple interpretations exist, present them — don't pick silently.
- If a simpler approach exists, say so. Push back when warranted.
- If something is unclear, stop. Name what's confusing. Ask.

This project's design questions have largely been resolved in writing — the spec's §19 "Resolved design questions," `ARCHITECTURE.md`, and `docs/adr/`. If a design question comes up, check there first before guessing; if it's genuinely not covered, that's exactly the kind of thing to surface rather than silently decide.

## 2. Simplicity First

**Minimum code that solves the problem. Nothing speculative.**

- No features beyond what was asked, and beyond what the current `ROADMAP.md` phase calls for. Don't pull forward a Phase 8 security beat while working on Phase 3.
- No abstractions for single-use code.
- No "flexibility" or "configurability" that wasn't requested — e.g. don't turn the risk table into a pluggable scoring framework or the two memory domains into a generic domain-registration system; the generality claim is proven by the Phase 6 line count, not by speculative plumbing.
- No error handling for impossible scenarios — but do implement the fail-closed handling `ARCHITECTURE.md` §7.3 explicitly calls for; that's a stated requirement, not speculative robustness.
- If you write 200 lines and it could be 50, rewrite it.

Ask yourself: "Would a senior engineer say this is overcomplicated?" If yes, simplify.

## 3. Surgical Changes

**Touch only what you must. Clean up only your own mess.**

When editing existing code:
- Don't "improve" adjacent code, comments, or formatting.
- Don't refactor things that aren't broken.
- Match existing style, even if you'd do it differently.
- If you notice unrelated dead code, mention it — don't delete it.

When your changes create orphans:
- Remove imports/variables/functions that YOUR changes made unused.
- Don't remove pre-existing dead code unless asked.

The test: every changed line should trace directly to the current task or `ROADMAP.md` item. This matters doubly here: the Phase 6 generality proof reports lines changed outside the domain agent, and the contest disclosure story depends on new work being cleanly visible in the history.

## 4. Goal-Driven Execution

**Define success criteria. Loop until verified.**

Transform tasks into verifiable goals:
- "Add the standing check" → "Write a test that flips an agent to DEGRADED mid-run and asserts its next low-risk proposal is held, then make it pass."
- "Implement the conflict rule" → "Write a test where a same-source-class flip above 0.70 is rejected and a different-class one commits, then make it pass."
- "Wire up the Sweeper" → "Expire a belief with no re-verification source and assert UNKNOWN(stale), excluded from recall, never deleted."

For multi-step tasks, state a brief plan:
```
1. [Step] → verify: [check]
2. [Step] → verify: [check]
3. [Step] → verify: [check]
```

Strong success criteria let you loop independently. Weak criteria ("make it work") require constant clarification. `ARCHITECTURE.md` §10 (Testing Strategy) already defines the verification criteria for every core guarantee, and each `ROADMAP.md` item carries a `verify:` line — use those as the source of "verify: [check]" rather than inventing new success criteria per task.

---

**These guidelines are working if:** fewer unnecessary changes in diffs, fewer rewrites due to overcomplication, phase boundaries in `ROADMAP.md` stay respected, and clarifying questions come before implementation rather than after mistakes.
