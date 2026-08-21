# ADR-001 — Firestore as the single belief store

**Status:** Accepted (revisit if a demo step ever needs a cross-dataset join; none does)

**Decision:** Firestore is the single store of truth for beliefs, evidence, the agent registry, and the audit stream's queryable projections. No relational database, no dedicated vector database.

**Reasoning, in order of weight:**

1. **The access pattern is exactly what a document store is for (primary reason).** Institutional memory is entity-keyed reads ("the beliefs for `inventory-api`") and append-only versioned writes (a new belief version with a supersession link, never an in-place update). There are no joins in the hot path, no aggregate reporting queries in v1, and the belief object (`ARCHITECTURE.md` §3.2) is a naturally nested document — history, evidence refs, decay schedule in one read.
2. **One store, one consistency story.** Splitting beliefs across a relational DB and a document/vector store means the supersession chain and the recall index can disagree about what's current. With one store resolving currency, the embedding index can safely be dumb (see ADR-005) — it returns IDs, and Firestore is the only authority on what those IDs currently mean.
3. **Operational cost during a deadline-bound build.** Managed, serverless, zero migration tooling, native Cloud Run IAM integration. A hackathon repo carrying Alembic-style migration machinery for a document-shaped problem is speculative complexity.

**What the vector index is not:** Vertex AI embeddings over belief statements serve recall nomination only. Embedding a "vector database" as the belief store is the exact wrong abstraction this project exists to argue against — a vector index has no notion of supersession, provenance, or currency (see the spec's §2 and ADR-005).

**Revisit when:** a real reporting/analytics need arrives (cross-entity aggregates, audit analytics at scale), or multi-region consistency requirements exceed Firestore's model.

**Alternatives considered:** PostgreSQL (relational modeling power this schema doesn't need, plus migration and connection-pool overhead on Cloud Run); a dedicated vector DB as primary store (category error — retrieval is an index, never the truth); Spanner (cost and ceremony wildly out of proportion for a two-domain demo).
