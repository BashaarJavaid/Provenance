# Roadmap

The build order for Provenance, sequenced so there's always something demoable at the end of each phase rather than a long stretch with nothing to show. Kept as a living checklist — update this file as items complete rather than letting it drift from reality: strike through a finished item (`~~…~~`) and append a `— **done**: …` note recording what actually shipped, including any deviation from the plan.

**Items 0.5 and 1 are done (Aug 21); item 2 is next.** Hard deadline: **August 31, 2026, 5:00 PM PDT** (All Things Agentic Hackathon); the hosted URL and credentials must stay valid through **October 1** for judging.

See [`ARCHITECTURE.md`](./ARCHITECTURE.md) for what each item actually means — its §10 Testing Strategy table is the source of the `verify:` criteria below — and [`docs/adr/`](./docs/adr/) for the reasoning behind the decisions items depend on. Phase 4 (memory) is the differentiator and gets the most time; phases 12–14 are submission mechanics with their own deadline pressure.

---

## Build Order

**Phase 1 — Foundations, deployed (nothing exists until it's on Cloud Run)**

0.5. ~~**Day-one dependency spike — before any code is written.** Three findings from auditing PortunusMCP as a dependency (see `docs/adr/ADR-004`), resolved in an hour, not discovered on Aug 25.~~
   — **done** (Aug 21): spike run against `portunusmcp==0.1.0` (PyPI) + `google-adk==2.7.1` in a Python 3.12 venv. All three findings resolved; `from services.gateway import signing, abac, decision` verified working alongside ADK, with an ECDSA sign/verify round-trip and an ABAC compile/evaluate round-trip.
   - **Package naming — confirmed.** The wheel ships a top-level package literally named `services`. **Provenance's own package is `provenance/`**, never `services/`. The `mypy` target in `CLAUDE.md` / `AGENTS.md` / `.cursor/rules/provenance.mdc` was updated to `provenance/` in this commit.
   - **Dependency resolution — `--no-deps`, and the failure mode is worse than a conflict.** `portunusmcp` pins `fastapi==0.115.6`; `google-adk` requires `fastapi>=0.133,<1`. A plain `pip install portunusmcp` does **not** error — it silently *downgrades* `fastapi` to 0.115.6 and `starlette` to 0.41.3, out of ADK's supported range, and pulls in `redis`, `sqlalchemy`, `asyncpg`, `alembic`, `mcp`, `uvloop`. Install is therefore two steps, and `portunusmcp` **cannot** go in `pyproject.toml`'s `dependencies`:
     ```
     pip install -e ".[dev]" && pip install --no-deps portunusmcp==0.1.0
     ```
     `cryptography` is declared as our own dependency (Portunus's `==49.0.0` pin is unnecessary — verified working on 50.0.0). `pip check` exits non-zero in the resulting venv by design; **CI must not gate on `pip check`**. Same two-step in the Dockerfile (Phase 1, item 3).
   - **Consumed surface — `signing`, `abac`, `decision`, and nothing else.** Verified per-module imports: `signing` needs only `cryptography` + stdlib; `abac` is pure stdlib; `decision` needs only `pydantic` (already an ADK transitive dep). `services/gateway/auth.py` — the identity broker — is **not consumed**: it requires `redis.asyncio`, `structlog`, `canonicaljson`, a YAML-loaded `PolicyEngine`, and a live Redis, none of which belong on Cloud Run for this. **Agent identity resolution is new code in this repo**: ECDSA-verify against the `public_key` on the Firestore registry record (item 5 stores it anyway) — the ADR-004-scored side of the boundary, not the pre-existing side.
   - **Short-lived credentials — confirmed absent; building the minting layer.** Portunus provides static API keys and HMAC-signed requests, no minting and no `expires_at` (the only TTLs are rate-limit counters). Decision: **build a thin minting layer** on top of Portunus's `signing` primitives — the registry mints an ECDSA-signed assertion `(agent_id, agent_version, issued_at, expires_at)`; the gateway verifies signature + expiry per request. New, scored work on the track's Agent Identity pillar; lands in **item 7**. `README.md` and `ARCHITECTURE.md` §2.1 keep their "short-lived per-agent credentials" wording — the claim becomes true rather than softened.
   - **Two constraints for item 7 to design around**, found in the wheel: `abac.ATTRIBUTE_ROOTS` is a fixed `{identity, tool, context, risk}` — Provenance conditions must live under those roots (`identity.standing`, `risk.score` map cleanly); and `decision.DecisionOutcome` is `allow / deny / challenge / human_approval_required`, so our approve/hold/deny vocabulary either maps `hold → human_approval_required` and ignores `challenge`, or we define our own typed decision. Not decided here.
   - **Also in the wheel, deliberately not imported:** `services/gateway/risk_engine.py` (per-call MCP risk scoring). It is a different thing from Provenance's deterministic action risk table, but a judge grepping the dependency will see "risk scoring" present in pre-existing code — the `README.md` disclosure row should say so explicitly before submission.
   - **Carried into item 1:** `tests/test_portunus_surface.py` holding the import + sign/verify + ABAC round-trip, so CI catches a `--no-deps` install that quietly stopped working or a Portunus API change.

1. ~~GCP project, ADK 2.0 project scaffold, Gemini 3.5 Pro/Flash access, Firestore provisioned, PortunusMCP added as a library dependency (per the item-0.5 resolution). Repo scaffold: `pyproject.toml`, lint/typecheck/test tooling, CI.~~ — verify: a fresh clone installs and `pytest` runs (zero tests is fine); CI is green.
   — **done** (Aug 21): both halves.
   - **Repo.** `pyproject.toml` (package `provenance/`; runtime deps `google-adk==2.7.1` + `cryptography` only), `provenance/__init__.py`, ruff / mypy-strict / pytest config, and `.github/workflows/ci.yml` running all four gates with no cloud credentials and no `pip check` gate. Verified: a fresh clone installs with the documented two-step command and `pytest` passes; dropping the `--no-deps` step turns the surface test red. CI green on push and PR ([#1](https://github.com/BashaarJavaid/Provenance/pull/1)).
   - **The item-0.5 carry-forward test** landed as `tests/test_portunus_surface.py`: sign/verify and ABAC compile/evaluate round-trips, plus `abac.ATTRIBUTE_ROOTS` and `decision.DecisionOutcome` pinned so an upstream change breaks the build instead of surprising item 7. Note for item 7: `signing.sign()` takes a hash **string**, not bytes.
   - **GCP.** `scripts/gcp_setup.sh` (idempotent, fails closed without linked billing) created `provenance-hackathon`, enabled `aiplatform` + `firestore`, and provisioned the Native-mode `(default)` Firestore database in `us-central1`. Re-running it is a no-op and exits 0.
   - **Deviation — Gemini 3.5 Pro does not exist.** The Vertex publisher catalog for this project lists `gemini-3-flash-preview`, `gemini-3.1-pro-preview`, `gemini-3.1-flash-*`, `gemini-3.5-flash`, `gemini-3.5-flash-lite`, and `gemini-3.6-flash` — no 3.5 Pro, and no GA Pro anywhere in the 3.x line (`gemini-3.1-pro`, `gemini-3.6-pro`, `gemini-3.5-pro-preview` all 404). Google shipped 3.x Flash-first; the only Pro-tier Gemini 3 is `gemini-3.1-pro-preview`, which does serve. This is not an allowlist, so there is nothing to request. Decision: stay on GA **`gemini-2.5-pro`** rather than a preview model that can change or be withdrawn during the Oct 1 judging window. **The four reasoning roles (Orchestrator, domain agents, Remediation Planner, Memory Analyst) run on `gemini-2.5-pro`**; verification stays on `gemini-3.5-flash`. `README.md` and `ARCHITECTURE.md` §5 were updated to name what is actually deployed. The model is a per-role config string, so swapping back is a one-line change if access appears.
   - **Also learned:** Gemini 3.x is served from the **`global`** endpoint, not a regional one — a regional probe 404s on models that are in fact available. The first version of the setup script got this wrong and reported a false negative on 3.5 Flash.
   - **Not pulled forward:** ADK is a dependency only — no `adk create` template, no root agent, no app (item 3 and Phase 3). Firestore, OpenTelemetry, and Vertex client libraries are not declared yet; each lands with the item that first imports it.

2. OpenTelemetry-compliant trace schema defined **before any agent is written** — span shapes for authorization decisions, belief commits, verification outcomes, reasoning chains; exported to Cloud Trace/Cloud Logging. — verify: a hand-emitted span for each shape renders in Cloud Trace with trace IDs intact.
3. A deployed Cloud Run service on day one (skeleton gateway + UI shell), plus deploy scripts. — verify: the service URL responds publicly; deploy is one command from a clean checkout.
4. Synthetic company base: `google/adk-samples` Customer Service entity model imported; `inventory-api` with config versions (known-good v41), 2–3 suppliers, two extra tier-2 services that never appear in an incident, and the fault-injection switch (ARCHITECTURE §9). — verify: a seed script populates Firestore idempotently; entities render in the UI shell.

**Phase 2 — Registry + Gateway + risk table (the authorization spine, before any agent exists)**

5. Agent Registry: the typed record (id, version, public_key, tool_scope, memory_domains, standing, rejection_window), stored in Firestore, with a request-time read API — never cached at boot. — verify: ARCHITECTURE §10 registry row — flip standing mid-run and the next read reflects it.
6. Typed Action schema + mechanical validation: `action_class` must exist in the tool registry, target in the entity model, declared fields validated against the tool schema; malformed → rejected once, escalated on the second. — verify: fabricated tool, nonexistent target, and free-form text all die before the gateway; second malformed emission escalates.
7. Agent Gateway: identity (PortunusMCP broker, short-lived per-agent credentials) → RBAC/ABAC → deterministic risk table (§4.2) → ECDSA-sign → approve / hold / deny. Every outcome, including denials, signed into the audit stream. — verify: table-driven tests over action_class × tier × blast × reversibility; the two worked examples score exactly 2 and 11.
8. **Denial-by-registry, proven before any agent exists**: a scripted proposal from a SUSPENDED identity is denied, and a DEGRADED identity's low-risk proposal is held for human approval regardless of score. — verify: both denials appear in the signed ledger citing the registry entry as cause. *(This is the demo's registry beat — a denial that happens because of a registry entry.)*

**Phase 3 — Incident #1 end to end (the fleet acts)**

9. Trigger stream + Orchestrator (classify → recall → route, wake-on-event) + SRE/Infra Agent + Remediation Planner emitting one typed Action with a pre-declared success predicate. — verify: the injected `inventory-api` error-rate spike produces exactly one typed `ROLLBACK_CONFIG` proposal, risk 2, auto-approved.
10. Execution path + Verification Agent (`CONFIRMED` path only for now) + first belief committed by a stub Policy Engine (full engine is Phase 4). — verify: rollback executes on the synthetic service, error rate drops, verification returns CONFIRMED against the predicate declared before execution.
11. Trace UI renders the incident as it runs: live fleet view + gateway ledger reading the one OpenTelemetry stream. — verify: a cold browser session can watch incident #1 end to end without console access.

**Phase 4 — Institutional memory (the differentiator — most time lives here)**

12. Typed Evidence (§3.3) + the versioned belief store in Firestore: append-only versions, supersession links, full history, entity-keyed reads. — verify: committing a superseding belief leaves the old version intact and linked; nothing is ever deleted.
13. Computed confidence (noisy-OR, §4.3) + the mechanical novelty check. — verify: ARCHITECTURE §10 confidence rows — unverified-claim-only evidence yields 0.00; restating one source N times equals stating it once; duplicate `(source_id, observed_at)` is not new.
14. Memory Policy Engine (the mirror pipeline, §2.2): standing check, domain authority, novelty, computed confidence vs thresholds (0.50 new / 0.70 + different-class for a flip), version + sign + COMMIT/REJECT. Memory Analyst recommends; the engine decides. — verify: a same-source-class flip attempt above 0.70 is rejected; with a different class it commits.
15. Retraction as a first-class transition + audit flagging of every action previously authorized on the retracted belief. — verify: ARCHITECTURE §10 retraction row.
16. Recall: exact-key entity reads + the Vertex AI embedding index over belief statements — index nominates IDs only; the store resolves currency and drops RETRACTED/UNKNOWN(stale). — verify: a RETRACTED belief that is the closest embedding match is never handed to the Orchestrator.
17. Seed the `SUP-042` AT_RISK belief + belief inspector UI (evidence, arithmetic, supersession chain, decay clock). — verify: the inspector shows the computed confidence breakdown for the seeded belief.
18. **Incident #2 — the fleet remembers**: same service, similar deviation; the Orchestrator recalls the prior belief before diagnosis completes and prioritizes the config-regression hypothesis. — verify: the recall event appears in the trace before the domain agent's first hypothesis.

**Phase 5 — Verification honesty (three-valued outcomes, exercised not designed)**

19. `REFUTED` and `INCONCLUSIVE` paths: negative beliefs written on confirmed refutation; nothing written on ambiguity; verification errors/timeouts treated as INCONCLUSIVE. — verify: fault-inject a failed rollback → REFUTED → negative belief; force ambiguity → INCONCLUSIVE → no write.
20. Bounded retry owned by the control loop: one re-plan with the refutation as input, then mandatory escalation. — verify: two consecutive REFUTED outcomes escalate; no third attempt occurs anywhere in the trace.

**Phase 6 — Second domain (generality proven with a number)**

21. Supply-Chain Agent + its registry entry, running the same incident loop. — verify: a supplier-disruption trigger routes, diagnoses, and proposes through the identical control plane.
22. Instrument the cost: report lines changed *outside* the domain agent file and registry entry. Target: **zero** control-plane changes (gateway, risk table, Policy Engine, Sweeper, orchestrator). — verify: the line-count report is committed; if the number isn't small, the control plane isn't general and the spec is wrong — better to find out now.

**Phase 7 — Class beliefs + Incident #3 (the generalization beat)**

23. Class-belief proposal path: ≥3 entity beliefs sharing a structural signature → Analyst proposes; confidence capped at 0.75 and below the weakest constituent; hard `ADVISORY ONLY` — may reorder investigation, may never authorize an action or evidence an entity-belief commit. — verify: an attempt to cite a class belief as commit evidence is rejected by the Policy Engine.
24. **Incident #3 — the fleet generalizes**: a deviation on `pricing-api`, never handled, empty entity memory; the class belief fires via the recall index and prioritizes the config-deploy hypothesis. — verify: the trace shows the class-belief nomination on an entity with zero entity beliefs. *(The single most important thirty seconds of the video.)*

**Phase 8 — Security beats (filters leak, the boundary holds)**

25. Model Armor templates wired on all ingest (injection/jailbreak + Sensitive Data Protection), verdicts logged to Cloud Logging. — verify: a blunt payload is blocked and logged; a crafted business-text payload clears the threshold (both narrated honestly — see THREAT_MODEL).
26. Gemma 4 sanitizer deployed in isolation (Vertex AI Model Garden): untrusted content → typed facts, PII tokenized, output is data never authority. — verify: raw inbound text never appears in any frontier-model prompt in the trace.
27. Injection arc end to end: the crafted payload leaks through both filters, the Supply-Chain Agent proposes `DISABLE_COMPLIANCE_CHECKS(SUP-042)`, the Planner types it honestly, the gateway scores **11** → HOLD. — verify: ARCHITECTURE §10 injection-arc row; the hold cites the risk arithmetic, not the payload.
28. Poisoning arc + standing: unverifiable "Supplier X is cleared" → weight 0.00 → rejected; three attempts inside the rolling window → **DEGRADED**, visible live on the registry panel; the agent's next ordinary low-risk proposal now requires human approval; SUP-042 still AT_RISK. — verify: ARCHITECTURE §10 poisoning + standing rows.

**Phase 9 — Staleness Sweeper (the second long-running async behaviour)**

29. Sweeper running continuously: on expiry, re-verify (CONFIRMED → refreshed version, decay reset; REFUTED → retraction path) or downgrade to `UNKNOWN(reason=stale)` — excluded from recall and confidence, never deleted. — verify: ARCHITECTURE §10 sweeper row, plus the downgrade visible in the belief inspector.

**Phase 10 — Human approval path (the Unlikely Hero surface)**

30. Approval queue with park/resume: a held incident parks via the ADK Task API, survives minutes of waiting, and resumes on approve/deny; nothing auto-approves on timeout. — verify: an incident parks ≥5 minutes and resumes cleanly; denial is signed into the ledger.
31. The plain-language approval card for the store operations manager: what the fleet wants to do, why, the component-by-component risk arithmetic, approve/deny — generated from the risk table, never from a model. — verify: a non-engineer can read the card for the score-11 action and articulate why it was held.

**Phase 11 — Counterfactual instrumentation (measured, not estimated)**

32. `--memory-disabled` A/B on incident #2: wall-clock, tool calls, tokens, hypotheses evaluated before the correct one. Full unedited side-by-side run recorded for the repo and blog post; the video shows only the result table. — verify: the A/B table is reproducible from the committed run artifacts.

**Phase 12 — Bonus artifacts (+1.0 max on a 5-point base — the margin in a tight field)**

33. Blog post (the determinism boundary, ARCHITECTURE §4, essentially already written) published on dev.to/Medium with the required disclosure line, embedding the full unedited A/B run. — verify: live URL.
34. Social post on X or LinkedIn with **#AllThingsAgenticHackathon**, linking video and repo. — verify: live URL.
35. Gemma 4 integration documented in the submission write-up as the additional Google AI model (+0.2 — one honest model beats three ornamental ones). — verify: the write-up section exists and matches what's deployed.

**Phase 13 — Cold-visitor test**

36. The hosted Cloud Run URL works for a first-time judge: approval queue included, credentials and step-by-step testing instructions in the README, verified valid through **October 1**. — verify: someone who has never seen the project completes the approval flow using only the README.

**Phase 14 — Rehearsal + submission**

37. Rehearse the full incident arc end to end, timed to **3:40** (rules evaluate only the first 4:00). Test several injection-payload variants so whichever Model Armor verdict occurs on camera is narrated honestly. — verify: a timed dry run lands at ≤3:40 with every beat intact, including the budgeted on-screen Cloud Run console + live service URL shot.
38. Record and publish the video (YouTube/Vimeo, public); finalize the repo (architecture diagram, reproducible spin-up instructions; if private, shared with testing@devpost.com and cloudhackathons@google.com); submit with the pre-existing-code disclosure table (README) verbatim in the submission text. — verify: the Devpost submission is complete before **Aug 31, 5:00 PM PDT**.

---

## Beyond the hackathon — documented, not built

Named here so they're deliberate deferrals, not gaps discovered by a judge:

- **Class-belief statistical rigor.** Generalizing from three observations is thin. The advisory-only cap and sub-constituent confidence ceiling bound the damage (a wrong class belief costs investigation order, never authorization); a production version needs a real minimum-support and validation policy. Trigger: any use beyond hypothesis ordering.
- **Verification against uncontrolled systems.** The synthetic environment means verification cannot fail the way production fails; the three-valued architecture is exactly what production needs, but predicates against real telemetry (and their flakiness) are unbuilt. Trigger: first non-synthetic deployment.
- **Standing restoration workflow.** Reinstatement is "explicit human action" — a real deployment needs an audited review flow for it, not a console flag-flip. Trigger: first real multi-team operation.
- **Multi-approver / escalation tiers.** One store-ops persona owns the queue; production wants routing, delegation, and out-of-office fallback. Trigger: more than one approver exists.
- **Memory domains beyond two.** The generality number (item 22) is the evidence the control plane scales; actually onboarding domains 3–N (with their own status vocabularies and half-lives) is future work. Trigger: demand.
