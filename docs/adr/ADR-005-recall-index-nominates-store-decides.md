# ADR-005 — Recall: the embedding index nominates, the belief store decides

**Status:** Accepted (this is the pre-emptive answer to "isn't this just RAG?")

**Decision:** Entity beliefs are recalled by exact key — no similarity search. Class beliefs are recalled through Vertex AI embeddings over belief *statements*, queried with the incident's typed facts — but the index returns **belief IDs and nothing else**. It never sees confidence, status, or currency. The store resolves each ID to its current version, drops anything `RETRACTED` or `UNKNOWN(stale)`, and hands the Orchestrator the governed object with its computed confidence and provenance chain.

**Reasoning, in order of weight:**

1. **Semantic similarity has no notion of *current* (primary reason).** A vector index over incident history retrieves *text similar to now*. It cannot answer "what do we currently believe about Supplier X" because it has no supersession, no provenance, no expiry, no way for a later fact to overrule an earlier one. Making the index authoritative would rebuild the exact wrong abstraction the project exists to argue against (spec §2). The embedding is the card catalog; the library decides what's on the shelf.
2. **Stale and retracted knowledge must be unreachable through the side door.** Retraction (§6.4) and staleness downgrades (§6.5) are only guarantees if *every* read path respects them. An index that returns full belief content would let a retracted belief keep informing diagnoses through its embedding. IDs-only makes the store the single choke point for currency — and the ARCHITECTURE §10 recall test seeds a RETRACTED belief as the closest match and asserts it never reaches the Orchestrator.
3. **Exact-key entity recall needs no ML at all.** A deviation on `inventory-api` reads the beliefs for `inventory-api`, mechanically. Similarity search is reserved for the one problem that actually is a similarity problem: matching a novel deviation to a class-belief statement.

**Revisit when:** class-belief volume makes nomination quality a measured bottleneck (better embeddings, reranking) — the division of labor (index nominates, store decides) is not up for revision.

**Alternatives considered:** classic RAG over incident history (retrieves similar text, not current truth — the anti-pattern); making the vector index the belief store (see ADR-001); keyword/tag matching for class beliefs (typed facts vs statement phrasing rarely share surface forms; this is the legitimate use case for embeddings).
