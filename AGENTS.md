# AGENTS.md

Project-specific context and instructions for Provenance, merged with a set of general behavioral guidelines (sections 1-4 below, adapted from [andrej-karpathy-skills/CLAUDE.md](https://github.com/multica-ai/andrej-karpathy-skills/blob/main/CLAUDE.md)) aimed at reducing common LLM coding mistakes: unstated assumptions, speculative complexity, unrelated edits, and vague success criteria.

**Tradeoff:** these guidelines bias toward caution over speed. For trivial tasks, use judgment.

---

## Project

Provenance — a fleet of agents that detects, diagnoses, fixes, and verifies enterprise incidents, and writes what it confirmed into a governed institutional memory. The claim: **an LLM never decides what the organization does, and never decides what the organization believes.** Full pitch in `README.md`. Hackathon deadline: **August 31, 2026, 5:00 PM PDT** (All Things Agentic Hackathon, Fortified Enterprise Fleet track).

## Where things live

- `README.md` — what this is, the architecture diagram, tech stack, pre-existing-code disclosure. Read this first.
- `ARCHITECTURE.md` — both decision pipelines, canonical typed objects, the determinism boundary, memory design, failure modes, observability, testing strategy, deployment. Load this when working on the gateway, the Memory Policy Engine, or any core loop logic.
- `THREAT_MODEL.md` — what's protected against, what isn't, and the assumptions the design rests on. Load this when working on anything security-relevant (gateway, risk table, memory writes, sanitizer, standing).
- `docs/adr/` — one file per architecture decision, including why several common alternatives weren't chosen. Load the specific ADR relevant to the component being touched, not all of them by default.
- `ROADMAP.md` — the fourteen-phase build order as a living checklist. Check this at the start of a session to see what's next; update it as items complete.
- `self-healing-enterprise-project-spec (1).md` — the original spec: demo script (§13), synthetic-company details (§12), submission logistics (§21). Load for demo/submission work.

Don't load `ARCHITECTURE.md`, `THREAT_MODEL.md`, or the ADRs in full for unrelated tasks (e.g. a pure UI tweak or demo-recording step) — pull in only the file relevant to the current task.

## Keeping the instruction files in sync

This project ships the same guidance in three tool-specific forms: `CLAUDE.md` (Claude Code), `AGENTS.md` (Codex), and `.cursor/rules/provenance.mdc` (Cursor). They are **not** auto-generated — keep them at parity by hand. Whenever you change any one of them — Commands, Current phase, Conventions, or any substantive guidance — mirror the change into the other two in the **same commit**, regardless of which tool you're working in. `CLAUDE.md` and `AGENTS.md` are near-identical (only the top `#` heading differs), so that edit is a straight copy; the Cursor rule carries the same content in its own form (frontmatter, `@file` mentions), so port the substance, not the formatting.

## Conventions

The four load-bearing properties from `ARCHITECTURE.md` §1.1 are hard rules, not guidelines — a change that violates one is wrong no matter how convenient:

- **No direct path from any reasoning agent to a state-mutating action.** The gateway is the only path. Don't add a second one "for testing" that could ship.
- **The memory write path mirrors the action path.** Probabilistic recommends, deterministic decides — for beliefs as for actions. The Memory Analyst never commits; the Policy Engine never reasons.
- **No LLM-generated number is an input to a deterministic decision.** Confidence comes from the published noisy-OR formula (`ARCHITECTURE.md` §4.3); risk comes from the lookup table (§4.2). If a change makes a model-asserted number decisive anywhere, it has crossed the determinism boundary — reject it.
- **The registry is read at request time, not at boot.** Don't cache standing.

Further conventions:

- Python 3.12, Google ADK 2.0, GCP (Cloud Run, Firestore, Vertex AI). Async throughout. No `localStorage`/browser-storage patterns in the backend.
- Agents emit **typed objects only**: the Planner emits the canonical typed Action (`ARCHITECTURE.md` §3.1), never free-form text; the Analyst emits typed evidence and recommendations. Don't invent new response shapes — reuse the four canonical objects in §3.
- Verification is three-valued (`CONFIRMED` / `REFUTED` / `INCONCLUSIVE`) and memory learns **only** from confirmed outcomes. Never write a belief on `INCONCLUSIVE` — no partial credit.
- Class beliefs are **advisory only**: they may reorder hypotheses; they may never authorize an action or serve as evidence for an entity-belief commit.
- Beliefs are append-only: supersession and retraction, never overwrite, never delete.
- Fail-closed is the default posture for any subsystem failure that would silently weaken a guarantee (`ARCHITECTURE.md` §7.3). If unsure whether something should fail open or closed, it's closed.
- No ML/LLM-based risk scoring — a deliberate constraint (see `docs/adr/ADR-003`), not a gap to fill in later.
- PortunusMCP is consumed strictly as a library dependency (identity, RBAC/ABAC, ECDSA signing). All track-facing authorization logic — risk table, registry standing, typed-action fields, hold/resume — is new code in this repo, and must stay visibly so in the commit history (contest disclosure requirement; see `README.md`).

## Commands

Built so far; this section grows as ROADMAP phases land (update to reality as commands are created):

- Local dev setup: `python3.12 -m venv .venv && .venv/bin/pip install -e ".[dev]" && .venv/bin/pip install --no-deps portunusmcp==0.1.0` — the second install is mandatory and cannot be folded into `pyproject.toml`; see ROADMAP item 0.5. `pip check` exits non-zero in this venv by design; CI must not gate on it.
- `.venv/bin/pytest` — tests
- `.venv/bin/ruff check .` — lint
- `.venv/bin/ruff format --check .` — formatting (fix with `ruff format .`)
- `.venv/bin/mypy provenance/` — strict type-check
- `./scripts/set_budget.sh` — the $300 billing budget with 50/90/100% alerts; idempotent (already run)
- `./scripts/gcp_setup.sh` — GCP project, APIs (incl. Cloud Trace and Cloud Run), the Cloud Build and Firestore (`roles/datastore.user`) IAM grants, Firestore, and a live Gemini access probe; idempotent. `PROJECT_ID` / `REGION` override the defaults (`provenance-hackathon`, `us-central1`)
- `./scripts/deploy.sh` — the one-command Cloud Run deploy; builds from the repo Dockerfile and curls `/health` on the deployed URL, exiting non-zero if it isn't 200. `PROJECT_ID` / `REGION` / `SERVICE` override the defaults. Live: https://provenance-808273007560.us-central1.run.app
- `GOOGLE_CLOUD_PROJECT=provenance-hackathon .venv/bin/python scripts/emit_trace_samples.py` — emits one span of each shape and reads the trace back from Cloud Trace; the item-2 `verify:` check. Needs credentials, so it is not in CI; allow up to ~4 minutes for indexing
- `GOOGLE_CLOUD_PROJECT=provenance-hackathon .venv/bin/python scripts/seed_firestore.py` — seeds the synthetic company into Firestore and reads all 26 documents back; the item-4 `verify:` check. Create-if-absent by default so a re-run never clobbers state a demo take changed; `--reset` restores the baseline. Needs credentials, so it is not in CI
- `GOOGLE_CLOUD_PROJECT=provenance-hackathon .venv/bin/python scripts/seed_registry.py` — writes the three agent registry records, generating each agent's keypair once and printing the private half once. Create-if-absent and deliberately **no `--reset`**: a re-run must never rewrite a stored `DEGRADED` back to `GOOD`. `--rotate <agent-id>` is the one path to a new key. Needs credentials, so it is not in CI
- `GOOGLE_CLOUD_PROJECT=provenance-hackathon .venv/bin/python scripts/verify_registry.py` — reads standing, flips it, re-reads through the same client in the same process, and restores; the item-5 `verify:` check. Exits non-zero if the flip isn't visible. Needs credentials, so it is not in CI
- `PROVENANCE_PLANNER_KEY="$(cat planner.pem)" GOOGLE_CLOUD_PROJECT=provenance-hackathon .venv/bin/python scripts/verify_gateway.py` — authorizes §4.2's two worked examples against the live registry, asserts 2/APPROVE and 11/HOLD, denies an unregistered id, verifies all three signatures, and reads the spans back from Cloud Trace asserting the components sum; the item-7 `verify:` check. Mutates nothing. The private key is an env var because `seed_registry.py` prints each once and stores it nowhere — `--rotate` mints a new one. Needs credentials, so it is not in CI
- `PROVENANCE_PLANNER_KEY="$(cat planner.pem)" GOOGLE_CLOUD_PROJECT=provenance-hackathon .venv/bin/python scripts/verify_denial_by_registry.py` — authorizes §4.2's score-2 rollback three times while flipping only the planner's stored `standing` (GOOD → APPROVE, SUSPENDED → DENY, DEGRADED → HOLD), then reads all three spans back from Cloud Trace asserting `stage="registry"` and the standing that caused each; the item-8 `verify:` check. **The one script that writes to live state** — the flips sit in a `try/finally` that restores the original standing on any exit path, including Ctrl-C. Refuses to run unless the record starts at `GOOD`. Needs credentials, so it is not in CI
- CI (`.github/workflows/ci.yml`) runs lint, format, type-check, and tests on push/PR — no cloud credentials

Still to come:

- Incident trigger / fault-injection scripts (Phase 3 / Phase 5)
- `--memory-disabled` counterfactual A/B runner (Phase 11)

## Cost ceiling

The GCP project runs on a **$300 free-trial credit and must not exceed it**, and the hosted demo has to stay alive through **October 1** judging. Trial credit also expires ~90 days after activation, so unspent credit is not banked. Treat the ceiling as a design constraint, not something to audit afterwards — billing data lags up to a day, so by the time a number looks wrong the money is already gone.

- **Before adding any paid resource** — a deployed model endpoint, a Cloud Run service with `min-instances > 0`, a scheduled job, anything with a GPU — state what it costs per hour and whether it bills **while idle**. Idle-billing resources are the only things that can realistically drain the credit.
- **The single largest risk is the Gemma 4 sanitizer** (`docs/adr/ADR-006`, Phase 8). A dedicated Vertex endpoint bills by the hour whether or not it serves a request — order $1–4/hr, which is the entire credit in under two weeks of being left up. Deploy it only while that beat is being built or recorded, and undeploy immediately after. Never leave it running overnight.
- **Cloud Run stays `min-instances=0`** with a low `max-instances`. Scale-to-zero is the default posture; an always-warm instance is a deliberate, justified exception, not a convenience.
- **Token spend is not the risk; loops are.** A Gemini call costs cents; an agent looping on one costs whatever it can reach. The bounded retry (Phase 5, item 20) and the escalation path are cost controls as much as correctness ones.
- **The backstop is a budget, not a habit.** `scripts/set_budget.sh` configures a $300 Cloud Billing budget with alerts at 50/90/100%. Alerts notify, they do not stop spend — the four rules above are the actual guardrail.

## Current phase

**Phases 1 and 2 are complete — items 1, 2, 3, 4, 5, 6, 7 and 8 are done (Aug 21); item 9 (the trigger stream, Orchestrator, SRE/Infra Agent and Remediation Planner — Phase 3, and the first agent code in the repo) is next.** The repo has `pyproject.toml` (package `provenance/`; runtime deps are `google-adk==2.7.1`, `cryptography`, `opentelemetry-exporter-gcp-trace`, `fastapi`, `uvicorn` and `google-cloud-firestore`), ruff / mypy-strict / pytest config, GitHub Actions CI that deliberately does not gate on `pip check`, and `tests/test_portunus_surface.py` guarding the consumed Portunus surface. ADK is a **dependency only** — no agent code: agents arrive in Phase 3. On the cloud side, `provenance-hackathon` exists with `aiplatform` + `firestore` + `cloudtrace` + `run` + `cloudbuild` + `artifactregistry` enabled and a Native-mode Firestore database in `us-central1`. **Gemini 3.5 Pro is not served to this project** (probed, 404 on every variant and endpoint), so the four reasoning roles run on `gemini-2.5-pro` and verification on `gemini-3.5-flash`; note that Gemini 3.x lives on the **`global`** endpoint, not a regional one.

**The trace schema (item 2) is now a contract to build against, not a convention.** `provenance/telemetry.py` defines four span shapes — `provenance.authorization.decision`, `provenance.belief.commit`, `provenance.verification.outcome`, `provenance.reasoning.chain` — documented in `ARCHITECTURE.md` §8.1. When a component from any later phase needs to emit, **use these helpers; do not call the OTel tracer directly and do not invent a fifth shape** without changing §8.1 and the tests together. Three rules the module enforces and `tests/test_telemetry_schema.py` guards: span attributes carry **identifiers, hashes, enums and numbers only — never content** (no payload text, prompt, model output or rationale prose); an emitted risk score must equal the sum of its four components; and a span that exits without recording an outcome is marked `ERROR`. Cloud **Logging** export is deliberately not wired — only Trace.

**The service is live (item 3):** https://provenance-808273007560.us-central1.run.app — one Cloud Run service, `provenance/app.py` (plain FastAPI) serving `GET /health` and `GET /` (the shell at `provenance/web/index.html`, one static file, no build step). `docs/adr/ADR-008` records why one service rather than §11's eventual four, why our own Dockerfile rather than `adk deploy cloud_run`, and why no UI framework. Three things to know before touching it: **use `/health`, never `/healthz`** — Cloud Run's frontend swallows that path and answers with its own 404 before the request reaches the container; the **Dockerfile's two-step install must stay two steps in that order** (`pip install .` then `pip install --no-deps portunusmcp==0.1.0`), same constraint as CI; and the service runs at `min-instances=0`, which is the posture the cost ceiling requires — do not raise it for convenience. Later items fill the shell's six labelled regions rather than restructuring it.

**The synthetic company is seeded (item 4).** `provenance/synthetic/company.py` holds the cast as frozen dataclasses; `scripts/seed_firestore.py` writes it to Firestore and reads every document back. Cymbal Home & Garden: `inventory-api` / `pricing-api` / `checkout-api` (all tier2), suppliers `SUP-042` (**tier1**) / `SUP-017` / `SUP-093`, approver Dana Ruiz, a `fault_injection/{target_id}` switch per service, and a small retail base. Four things to know before touching it: **`inventory-api` is tier2 and `SUP-042` is tier1** — that is the only route §4.2's worked examples have to the frozen scores 2 and 11, and `tests/test_synthetic_company.py` asserts both by name; **no entity document carries a status** — `SUP-042` becomes AT_RISK through the belief store in item 17, never as a seeded field, and a test rejects any `status`/`confidence`/`belief` field on the entity dataclasses; the seed is **create-if-absent** so a re-run cannot clobber mid-rehearsal state, and its read-back therefore content-checks only what that run wrote (`--reset` rewrites and checks everything); and `google-cloud-firestore` moved from **dev** to a runtime dependency in item 5, when `provenance/registry.py` became the first importer inside the package. Schema reasoning in `docs/adr/ADR-009`.

**The agent registry is live (item 5) — Phase 2's authorization spine begins here.** `provenance/registry.py` holds §3.4's record, the async read API, and `set_standing()`, the single writer; `scripts/seed_registry.py` writes the three agents (`sre-infra-agent`/`infrastructure`, `supply-chain-agent`/`supply-chain`, `remediation-planner` with §4.2's two action classes and no memory domain) and `scripts/verify_registry.py` performs the live flip. Five things to know before touching it: **`get_agent()` reads Firestore on every call and must stay that way** — §1.1's fourth property, and both the offline test and the live script fail the moment anything memoizes; **no function returns `Agent | None`** — `RegistryUnavailable` / `AgentNotRegistered` / `RegistryError` are what item 7 catches and maps to `DENY(stage="registry")`, and a test rejects any optional-`Agent` return type; the **stored `standing` is authoritative and never recomputed from `rejection_window`**, because `SUSPENDED` isn't derivable and reinstatement needs a field a human can set; the rolling window is now a number — **3 rejections inside 24 hours** (`REJECTION_THRESHOLD` / `REJECTION_WINDOW_HOURS`), with `degraded_by_window()` shipped for item 14 but deliberately not called on read; and the seeder has **no `--reset`** and skips existing records whole, so re-seeding can neither forgive a DEGRADED agent nor rotate a key item 7 has minted. Schema reasoning in `docs/adr/ADR-010`.

**The typed Action and its validation are live (item 6) — §2.1 stage 1, the gateway's front door.** `provenance/tools.py` is the tool registry; `provenance/action.py` holds §3.1's eight-field Action, `validate()`, the `ActionError` hierarchy and `outcome_for()`; `tests/test_action.py` is the entire `verify:` line — item 6 is the **first item with no live script**, because it touches no cloud service at all. Seven things to know before touching it: the **tool registry is a frozen constant, not Firestore, and that is deliberate** — §1.1's request-time rule exists because standing changes mid-run, and nothing analogous is true of a tool, so `TOOLS` holds two entries with four fields each (`action_class`, `target_kind`, authoritative `reversible`, authoritative `blast_radius`) and **no `base[action_class]`**, which stays in item 7's table with the other three components; **`validate()` takes `object`, not `dict`** — §10 names free-form text as a rejection case and it is only testable if a bare string can be handed in, so a `str`, `None`, a list and a wrong-keyed dict all raise; **nothing returns an optional `Action` or `Tool`**, guarded by the same reflection test item 5 used, because a forgotten `if action:` at stage 1 means the gateway scores something never validated and no later stage catches it; **the tool registry is authoritative over the Planner** for `reversible` and `blast_radius`, and the entity model over `target_tier`, so a Planner misdeclaring any of the three raises `FieldMismatch` (§3.1's "not vibes"); **there is no `params` field and §3.1 stays at eight** — item 10's executor reads `known_good_version` off the entity model rather than trusting a Planner-supplied version, and a test asserts its absence; `outcome_for()` is **stateless** (`MALFORMED_RETRY_BUDGET = 1`) because §7.1 gives the count to the control loop, not the agent; and `validate()` is **sync**, the one deliberate exception to async-throughout, since it reads two frozen tuples and does no I/O. Also added: `company.service(id)` / `company.supplier(id)` (raising `KeyError`) and `telemetry.TargetKind` — **no span shape changed**. Schema reasoning in `docs/adr/ADR-011`.


**The Agent Gateway is live (item 7) — §2.1's pipeline, and the only path to a state-mutating action.** Three modules: `provenance/risk.py` (§4.2's table), `provenance/credentials.py` (stage 2's signed assertion), `provenance/gateway.py` (the pipeline, whose `authorize()` is its single entry point). `scripts/verify_gateway.py` is the live half. Schema reasoning in `docs/adr/ADR-012`. Ten things to know before touching it:

- **`authorize()` takes `object`, not an `Action`, and that is load-bearing.** It runs `action.validate()` itself as stage 1, which is what makes `DENY(stage="schema")` reachable and what guarantees nothing reaches the risk table unvalidated — §1.1 property 1 made structural rather than documentary. **Every terminal outcome is a returned `Decision`, never a raised exception**; a test asserts `authorize` is the module's only public coroutine, because a second door is the whole security story.
- **The agent signs its own credential.** §2.1 said "minted by the registry **and** verified against the agent's registered `public_key`", which cannot both be true — ADR-010 stores no private halves. Resolved in favour of: the registry *issues and registers* the keypair (`--rotate` is the one path to a new one), the agent holds the private half and signs. `CREDENTIAL_TTL_SECONDS = 300`.
- **The registry read physically precedes the identity check**, because the public key stage 2 verifies against is a field on the record stage 3 fetches. The recorded `stage=` is still §2.1's. Do not "fix" the ordering.
- **`proposed_by` is checked against the credential**, and a credential for a superseded `agent_version` is denied. Without the first, an authenticated agent could present its own valid credential beside an action attributed to somebody else; without the second, `--rotate` revokes nothing.
- **RBAC and ABAC are two checks and must stay two.** Tool scope is a plain `in` (that is what role-based means); the standing rule goes through Portunus `abac.compile_condition`/`evaluate`, whose grammar has no `in` operator. A test asserts the compiled `abac.Condition` object, so removing the dependency fails the build rather than silently falsifying ADR-004's disclosure.
- **A DEGRADED hold is scored; a SUSPENDED denial is not.** DEGRADED returns `HOLD, stage="registry", reason="STANDING_DEGRADED"` carrying the full §4.2 arithmetic, because §3.4's "regardless of risk score" only means something if the score exists and item 31's card renders it. A denial carries no score.
- **The `authorization.decision` span's fields below `agent.{id,version}` are now optional** — the one amendment to item 2's contract, made with §8.1 and `tests/test_telemetry_schema.py` in the same commit. Pre-standing denials had no way into the audit stream otherwise. **Absent means omitted, never emitted empty**, and out-of-vocabulary values still raise. Still four shapes; no new attribute key.
- **`risk.BASE` is the only home of `base[action_class]`** (`ROLLBACK_CONFIG` 1, `DISABLE_COMPLIANCE_CHECKS` 4 — fixed by §4.2's worked examples). A test asserts its key set equals `tools.TOOLS`'s action classes, so a third tool cannot ship without a base score. **`risk.band()` never returns `DENY`**: every denial comes from who is asking, never from the score.
- **`Decision` is ours, not Portunus's**, typed with `telemetry.AuthOutcome` / `AuthStage` so the object and the span cannot drift — this closes item 0.5's open question. Its `subject` field (`agent@version|action_class|target`) is signed, so a signature cannot be lifted from one action onto another.
- **The gateway's signing key is ephemeral per process** — a marked `ponytail:` shortcut with Secret Manager as the named upgrade path. Decisions verify against `gateway.public_key_pem()` from the same run, not across a Cloud Run restart; `THREAT_MODEL.md` states this rather than letting "signed" imply otherwise.

Two pieces of infrastructure arrived with it: `[[tool.mypy.overrides]] module = "services.*"` in `pyproject.toml` (portunusmcp ships no `py.typed`; scoped to that one distribution, everything we write stays `--strict`), and `tests/conftest.py` holding the one global `TracerProvider` — OpenTelemetry allows it to be set once, and with two span-emitting test modules the second `set_tracer_provider()` was being ignored, silently starving that module's exporter.

**Registry state note:** `remediation-planner` is at **`v3`** — items 7 and 8 each ran `seed_registry.py --rotate` once, because each printed private half is shown exactly once and stored nowhere (ADR-010). Standing and `rejection_window` survive a rotation; only the key and version move. **Read `agent.version` off the record rather than hardcoding it** — `scripts/verify_gateway.py` and `scripts/verify_denial_by_registry.py` both do, which is why a rotation costs them nothing. A proposal's `proposed_by` must match the stored version or the gateway denies at `stage="identity"` — that is the version-binding check working.


**Denial-by-registry is proven live (item 8) — Phase 2 closes here.** One new file, `scripts/verify_denial_by_registry.py`, and **no change under `provenance/` at all**: item 7 had already built every mechanism item 8 names, so item 8 is the live proof, not new code. It authorizes §4.2's score-2 `ROLLBACK_CONFIG(inventory-api)` three times against the live registry while the only thing that changes between runs is the stored `standing` — `GOOD` → APPROVE at 2, `SUSPENDED` → DENY unscored, `DEGRADED` → HOLD *carrying* the 2 — then reads all three spans back from Cloud Trace. Four things to know before touching it: **"the signed ledger" is the span stream, not a UI** — §8.2's ledger surface is item 11's and item 8 renders nothing, so the `verify:` line is checked by asserting `decision.stage`, `decision.reason`, `agent.standing` and a non-empty `decision.signature` on what actually landed in Cloud Trace; **the GOOD control run is load-bearing**, because without it "denied" and "held" could be caused by something about the action rather than by the registry entry; **the flips sit in a real `try/finally`**, a deliberate departure from `scripts/verify_registry.py`'s unconditional restore line, because `seed_registry.py` has no `--reset` and a crash between the flip and the restore would strand the fleet's only tool-scoped agent as `SUSPENDED` with no path back but a hand-written `set_standing` — exercised with a simulated Ctrl-C, not assumed; and the script **refuses to run against a non-GOOD record**, since the control would prove nothing and the restore would cement the stranded value. No ADR and no new offline tests: item 8 rejects no alternative ADR-012 has not recorded, and item 7's three DEGRADED/SUSPENDED tests already are the offline half.

Alongside this sits the documentation suite (this file, `README.md`, `ARCHITECTURE.md`, `THREAT_MODEL.md`, `ROADMAP.md`, `docs/adr/`) and the original spec. The item-0.5 constraints all hold in the scaffold: the package is **`provenance/`** (a local `services/` would shadow the installed `portunusmcp`), `portunusmcp` installs as a **separate `--no-deps` step** and must never be added to `pyproject.toml`, and CI does not gate on `pip check`. See `ROADMAP.md` for the full build order; update this section as phases complete, recording what shipped and any deviations, the way each completed item gets a `— **done**:` note in the roadmap.

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
