# ADR-006 — Untrusted content is sanitized by an isolated Gemma model, never raw to a frontier model

**Status:** Accepted

**Decision:** All untrusted external content (supplier alerts, third-party feeds, anything not emitted by our own instrumented systems) passes through Model Armor screening and then a sanitizer running **Gemma 4** (E4B/12B, served via Vertex AI Model Garden) in isolation, which reduces it to typed facts and tokenizes residual PII. Raw untrusted text never appears in a prompt to Gemini 2.5 Pro / 3.5 Flash. The sanitizer's output is data, never authority.

**Reasoning, in order of weight:**

1. **Blast-radius containment for prompt injection (primary reason).** The reasoning agents hold tool access and memory-write authority; the sanitizer holds neither. If adversarial text is going to manipulate a model, let it manipulate the model that can't do anything — worst case is a corrupted *fact*, which then still faces the typed-action schema, the risk table, and the evidence arithmetic downstream. This is honest layering: `THREAT_MODEL.md` states plainly that the sanitizer leaks (the demo payload survives it as a fact that still prompts a dangerous proposal), and the boundary remains the gateway.
2. **A small isolated open model is the right tool for extraction.** Reducing messy text to typed facts is exactly the job LLMs are for (`ARCHITECTURE.md` §4.4's last row) and doesn't need frontier reasoning. Isolation (separate deployment, no tools, no memory authority) is what matters; Gemma's size makes that isolation cheap to run.
3. **Scored bonus, honestly earned.** An additional Google AI model integration is worth +0.2 (spec §21). Gemma-as-sanitizer strengthens the security story rather than decorating it — one honest model integration beats three ornamental ones.

**Position in the stack:** Model Armor (managed screening, the guardrail the track brief names) runs first; the sanitizer second; neither is the boundary. See the injection row of `THREAT_MODEL.md`.

**As built (ROADMAP item 26):** the isolation contract above is unchanged; the serving model named above is. Probing found `gemma-4-26b-a4b-it-maas` — serverless, so no endpoint is deployed and nothing bills while idle — and found that Gemma ignores `responseSchema`, so a strict parser rather than a schema is what makes the output typed. Both, and the PII leak the first live run caught, are recorded in [`ADR-028`](./ADR-028-the-gemma-sanitizer-as-built.md).

**Revisit when:** structured-extraction quality on real inbound formats proves insufficient at Gemma's size — swap the model, keep the isolation contract.

**Alternatives considered:** feeding raw input to Gemini with "be careful" system prompting (the system prompt is never the security boundary); regex/rule-based sanitization only (can strip patterns but can't extract typed facts from prose); Model Armor alone (screening filters classify, they don't reduce content to a typed representation — and classifiers miss things, which is exactly why there are layers).
