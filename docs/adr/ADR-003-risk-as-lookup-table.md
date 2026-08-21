# ADR-003 — Risk is a deterministic lookup table, no ML/LLM scoring

**Status:** Accepted (deliberate constraint, not a gap to fill in later)

**Decision:** Action risk is a pure function of the typed action, computed by table lookup: `base[action_class] + criticality_points[target_tier] + blast_points[blast_radius] + irreversibility_points[reversible]`, with fixed outcome bands (0–3 auto-approve, 4–6 approve-with-notification, 7+ hold for human). No model-generated score, no learned risk model, no "AI risk assessment."

**Reasoning, in order of weight:**

1. **The gateway must be impossible to persuade (primary reason).** The whole security story (`THREAT_MODEL.md`, injection row) is that an instruction embedded in data cannot talk its way past authorization. That holds only if the risk function's inputs are properties the action *objectively has* — declared fields validated against the tool schema — and never text. An ML scorer reintroduces a channel adversarial input can push on; a table cannot be phrased at.
2. **Explainability is the governance surface.** The approval card shows the store operations manager the component-by-component arithmetic (base 4, tier-1 +2, org-wide +2, irreversible +3 = 11). That plain-language explainability is precisely what makes non-technical governance possible — a stated judging criterion. A model score of "11" explains nothing.
3. **Auditability.** Every held or denied action's score is reproducible from the table and the typed action, forever. Signed ledger rows stay verifiable without archiving model versions.

**The numbers are principled, not fitted to the demo:** disabling a compliance control scores 11 because it mutates a safety control on a tier-1 target org-wide and cannot be un-occurred; a reversible single-service rollback to a known-good prior scores 2. Reversibility and blast radius are declared fields validated against the tool schema — the registry, not the Planner's mood, is authoritative.

**Revisit when:** never within this project's claim. A production successor might add table *entries* or new additive factors; replacing the lookup with a learned scorer abandons the determinism boundary.

**Alternatives considered:** LLM risk assessment (persuadable, unexplainable, unauditable — the anti-pattern); trained anomaly-scoring models (no training data, and drifts silently); per-action hardcoded outcomes without arithmetic (loses the additive explanation the approval card is built from).
