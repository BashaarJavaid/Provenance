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
