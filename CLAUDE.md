# CLAUDE.md

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
- `./scripts/gcp_setup.sh` — GCP project, APIs, Firestore, and a live Gemini 3.5 access probe; idempotent. `PROJECT_ID` / `REGION` override the defaults (`provenance-hackathon`, `us-central1`)
- CI (`.github/workflows/ci.yml`) runs lint, format, type-check, and tests on push/PR — no cloud credentials

Still to come:

- Firestore seed script for the synthetic company (Phase 1, item 4) — idempotent
- Cloud Run deploy — one command from a clean checkout (Phase 1, item 3)
- Incident trigger / fault-injection scripts (Phase 3 / Phase 5)
- `--memory-disabled` counterfactual A/B runner (Phase 11)

## Current phase

**Phase 1 item 1 is done (Aug 21); item 2 is next.** The repo has `pyproject.toml` (package `provenance/`; runtime deps are `google-adk==2.7.1` + `cryptography` only), ruff / mypy-strict / pytest config, GitHub Actions CI that deliberately does not gate on `pip check`, and `tests/test_portunus_surface.py` guarding the consumed Portunus surface. ADK is a **dependency only** — no agent code, no app: agents arrive in Phase 3, the Cloud Run skeleton in item 3. On the cloud side, `provenance-hackathon` exists with `aiplatform` + `firestore` enabled and a Native-mode Firestore database in `us-central1`. **Gemini 3.5 Pro is not served to this project** (probed, 404 on every variant and endpoint), so the four reasoning roles run on `gemini-2.5-pro` and verification on `gemini-3.5-flash`; note that Gemini 3.x lives on the **`global`** endpoint, not a regional one. Alongside this sits the documentation suite (this file, `README.md`, `ARCHITECTURE.md`, `THREAT_MODEL.md`, `ROADMAP.md`, `docs/adr/`) and the original spec. The item-0.5 constraints all hold in the scaffold: the package is **`provenance/`** (a local `services/` would shadow the installed `portunusmcp`), `portunusmcp` installs as a **separate `--no-deps` step** and must never be added to `pyproject.toml`, and CI does not gate on `pip check`. See `ROADMAP.md` for the full build order; update this section as phases complete, recording what shipped and any deviations, the way each completed item gets a `— **done**:` note in the roadmap.

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
