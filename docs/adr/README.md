# Architecture Decision Records

One file per consequential architecture decision. Load the specific ADR relevant to what you're working on rather than all of them.

- [`ADR-001-firestore-single-store.md`](./ADR-001-firestore-single-store.md) — Firestore as the single belief store (no relational DB, no vector DB as primary)
- [`ADR-002-computed-confidence.md`](./ADR-002-computed-confidence.md) — Confidence computed by a published noisy-OR formula, never LLM-asserted
- [`ADR-003-risk-as-lookup-table.md`](./ADR-003-risk-as-lookup-table.md) — Risk as a deterministic lookup table, no ML/LLM scoring
- [`ADR-004-portunusmcp-as-library.md`](./ADR-004-portunusmcp-as-library.md) — PortunusMCP consumed as a library dependency (pre-existing-code containment)
- [`ADR-005-recall-index-nominates-store-decides.md`](./ADR-005-recall-index-nominates-store-decides.md) — Recall: the embedding index nominates, the belief store decides (vs plain RAG)
- [`ADR-006-gemma-sanitizer-isolation.md`](./ADR-006-gemma-sanitizer-isolation.md) — Untrusted content sanitized by isolated Gemma, never raw to a frontier model
- [`ADR-007-adk-orchestration-park-resume.md`](./ADR-007-adk-orchestration-park-resume.md) — ADK Graph Runtime orchestration; Task API for the park/resume approval path
- [`ADR-008-one-cloud-run-service.md`](./ADR-008-one-cloud-run-service.md) — One Cloud Run service, our own Dockerfile, no UI framework (vs `adk deploy cloud_run`, vs a Node toolchain)
- [`ADR-009-synthetic-company-collections.md`](./ADR-009-synthetic-company-collections.md) — Typed Firestore collections for the synthetic company; the fault switch is data, not deploy config
- [`ADR-010-agent-registry-record.md`](./ADR-010-agent-registry-record.md) — The agent registry record: flat `agents/{id}`, stored standing authoritative, the rolling window given a number
- [`ADR-011-tool-registry-and-action-validation.md`](./ADR-011-tool-registry-and-action-validation.md) — The tool registry as a constant (not Firestore), the Action's eight fields and no `params`, validation that raises
- [`ADR-012-the-gateway.md`](./ADR-012-the-gateway.md) — The gateway: the agent signs its own credential, RBAC and ABAC split, a `Decision` of our own, and an ephemeral signing key
- [`ADR-013-trigger-stream-and-incident-graph.md`](./ADR-013-trigger-stream-and-incident-graph.md) — The trigger stream as a guarded HTTP route (vs a Firestore listener), the incident loop as a real ADK graph, and `Trigger` as a non-canonical object
- [`ADR-014-execution-and-the-stub-policy-engine.md`](./ADR-014-execution-and-the-stub-policy-engine.md) — The executor re-checks the signed decision (not just its branch), `known_good_version` from the entity model, and a stub Policy Engine that refuses a v2 rather than writing an unlinked one
- [`ADR-015-the-trace-ui.md`](./ADR-015-the-trace-ui.md) — The trace UI reads an in-process span buffer (vs Cloud Trace read-back), captures spans at start so in-flight agents are visible, polls rather than streams, and stays one static file
- [`ADR-016-the-versioned-belief-store.md`](./ADR-016-the-versioned-belief-store.md) — One immutable document per belief version, backlinks derived on read, no `current_version` pointer, and a status flip refused rather than approximated
- [`ADR-017-novelty-and-the-accumulated-evidence-set.md`](./ADR-017-novelty-and-the-accumulated-evidence-set.md) — Novelty compares `(source_id, observed_at)` pairs, a version rests on everything it ever rested on, and nothing new is a terminating refusal
- [`ADR-018-the-conflict-rule-and-the-standing-counter.md`](./ADR-018-the-conflict-rule-and-the-standing-counter.md) — §6.3 as a set difference over the classes a belief rests on, two failures under their existing names, and only evidence-shaped refusals costing standing
- [`ADR-019-retraction-and-the-audit-ledger.md`](./ADR-019-retraction-and-the-audit-ledger.md) — Retraction is §6.4's rule and not §6.3's, and flagging the actions that rested on a belief needs a ledger nothing else was going to build
- [`ADR-020-recall-as-built.md`](./ADR-020-recall-as-built.md) — Recall as built: query-time embeddings with no stored vectors and no index endpoint, and the statement on the belief's root document so the index cannot see status or confidence
- [`ADR-021-the-belief-inspector.md`](./ADR-021-the-belief-inspector.md) — The belief inspector as the UI's second data source (content cannot ride on spans), reading live Firestore, with one implementation of §4.3
- [`ADR-022-the-refuted-and-inconclusive-paths.md`](./ADR-022-the-refuted-and-inconclusive-paths.md) — A refutation commits a negative belief rather than retracting the confirmed one, and ambiguity is forced by making verification not happen (vs a model asked to hedge)
- [`ADR-023-the-bounded-retry.md`](./ADR-023-the-bounded-retry.md) — The bounded retry: two budgets rather than one shared count, the loop owning it rather than an agent, and a re-plan stamped with its own observation time so the second commit is not refused as a repeat
- [`ADR-024-the-second-domain.md`](./ADR-024-the-second-domain.md) — The second domain: the graph, the state seeding and the Orchestrator's vocabulary all comprehended out of one `DOMAINS` dict, a fail-closed routing kind check, and `half_life_domain` as a per-domain lookup whose two values are equal
- [`ADR-025-class-beliefs-and-the-advisory-cap.md`](./ADR-025-class-beliefs-and-the-advisory-cap.md) — Class beliefs: the advisory cap as a refusal that costs standing (not a label), confidence capped below the weakest constituent by a published margin, evidence derived rather than proposed, and the Analyst as a seeder rather than a graph node
- [`ADR-026-incident-three-and-the-cold-entity.md`](./ADR-026-incident-three-and-the-cold-entity.md) — Incident #3: a cold entity's incident correctly ends `ESCALATED` without executing, the causation claim is the dead hint and not an A/B, and the flake rate is measured before the demo depends on it
