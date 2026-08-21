# ADR-002 — Confidence is computed by a published formula, never LLM-asserted

**Status:** Accepted (load-bearing; changing this dissolves the project's central claim)

**Decision:** Belief confidence is computed deterministically — noisy-OR over distinct evidence source classes, weighted by a published `base_weight` table and decayed by age (`ARCHITECTURE.md` §4.3). No LLM ever asserts, adjusts, or overrides a confidence number. The Memory Analyst's role ends at extracting typed evidence and recommending; if it emits a number, the Memory Policy Engine discards it.

**Reasoning, in order of weight:**

1. **This is where these architectures quietly cheat (primary reason).** The common pattern moves authority into code in the diagram while the code's decisive input remains a model's opinion — "the policy engine commits if confidence ≥ 0.7" where confidence is whatever the LLM said. That is a cosmetic determinism boundary. A real one requires the number itself to come from a published formula over typed inputs.
2. **The poisoning defense falls out of the arithmetic.** `unverified_external_claim` has base weight 0.00, so a bare assertion moves confidence by exactly nothing — no classifier deciding whether input "smells adversarial." Distinct-source-class combination means repetition can't inflate confidence. Age decay means unre-confirmed beliefs weaken on their own and eventually trip the Sweeper.
3. **Explainability for a non-engineer.** The belief inspector shows the arithmetic — which evidence, which weights, which decay. A model-asserted 0.94 explains nothing; a computed 0.94 is an audit trail.

**The weights are honest engineering judgment, not ground truth.** The `base_weight` table is hand-chosen and published; its defense is that it is *inspectable and fixed*, not that it is optimal. Tuning weights is legitimate future work; making them model-output is not.

**Revisit when:** real-world calibration data exists to fit the weights against — the *structure* (published formula over typed source classes) is not up for revision.

**Alternatives considered:** LLM-asserted confidence (the cheat this ADR exists to forbid); Bayesian networks with learned parameters (nothing to learn from at n=one-demo, and opaque to the approval-card audience); simple evidence counting (can't express source-quality differences, which the 0.00 weight for unverified claims depends on).
