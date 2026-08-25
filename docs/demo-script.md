# The demo — one continuous incident arc

**What this is:** the demo choreography, lifted verbatim from
[`self-healing-enterprise-project-spec (1).md`](<../self-healing-enterprise-project-spec (1).md>)
§13 so that ROADMAP Phases 12–14 can point at a live document instead of into a frozen
spec. **The beats below are unedited spec text.** Only this header and the reference table
are new.

Cross-references in the body use the spec's own section numbers. Their current homes:

| Spec § | Now lives in |
|---|---|
| §1 the claim | [`README.md`](../README.md) |
| §8.4 class beliefs | [`ARCHITECTURE.md`](../ARCHITECTURE.md) §6.2 |
| §8.6 decay / Sweeper | `ARCHITECTURE.md` §6.5 |
| §8.7 recall | `ARCHITECTURE.md` §6.6 |
| §10 the injection payload | `ARCHITECTURE.md` §5.1, [`THREAT_MODEL.md`](../THREAT_MODEL.md) |
| §12 the synthetic company | `ARCHITECTURE.md` §9 |
| §21 bonus + submission | [`docs/submission.md`](./submission.md) |

**One drift to narrate honestly:** incident #3's beat says the class belief fires on
`pricing-api` and the config-deploy hypothesis is prioritized. As built (ROADMAP item 24)
the class belief *is* nominated, survives the currency filter and reaches the agent's
prompt before the first hypothesis — but the incident ends `ESCALATED`, because the
executor refuses an action `pricing-api` cannot receive, and item 32's A/B is still where
the causation number comes from. See `ARCHITECTURE.md` §6.2 and `ADR-026`.

---

## 13. The demo — one continuous incident arc

One story, rising stakes, **3:40 target** — the rules evaluate only the first 4:00 of video, and the closing claim does not get to fall off the edge. Every beat below is a claim the architecture makes, filmed live and unedited (the criteria reward exactly that). One beat is mandatory bookkeeping and gets its own budgeted seconds rather than being hoped into the corner of a terminal: **an on-screen shot of the Cloud Run console and the live service URLs** — the rules require visible proof the backend runs on Google Cloud.

**Incident #1 — the fleet acts.**
`inventory-api` error rate spikes to 38% six minutes after a config deploy. No relevant memory yet — a cold case. SRE Agent diagnoses a config regression. Planner emits a typed action (reversible, single-service, tier-2). Gateway scores **2** → auto-approve, signed. Rollback executes; error rate drops to ~1%; Verification returns `CONFIRMED` against its pre-declared predicate. Policy Engine computes confidence from one `verified_system_observation` and commits the belief. On-screen: the belief object being written, with its computed number and its evidence IDs.

**Incident #2 — the fleet remembers, and the numbers are measured, not estimated.**
Same service, similar deviation. Orchestrator recalls the prior belief before diagnosis completes; the config-regression hypothesis is prioritized instead of being one of several. On screen for ten seconds: the measured A/B table — wall-clock, tool calls, tokens, hypotheses evaluated before the correct one — from running the same incident with `--memory-disabled`. The full, unedited side-by-side run lives in the repo and the blog post (§21); the video spends its seconds on the result, not the ceremony. Live LLM runs vary, and a 60-second live A/B is the single most failure-prone thing a demo can contain — so it isn't in the demo.

**Incident #3 — the fleet generalizes.**
A deviation on `pricing-api`, a service the fleet has **never handled**. Entity memory is empty. The class belief from §8.4 fires via the recall index (§8.7), and the config-deploy hypothesis is prioritized on a brand-new entity. This is the beat that separates institutional learning from caching, and it is the single most important thirty seconds of the video.

**The attack — someone tries to corrupt what it learned, twice, and fails twice.**
The §10 payload arrives. Model Armor screens it — the crafted payload clears the threshold; the sanitizer reduces it to a fact; the Supply-Chain Agent proposes the dangerous action anyway. We say out loud that both outer layers leaked. The Gateway scores it **11** → held → and the approval card lands in front of the **store operations manager** in plain language. She denies. Separately, a compromised agent attempts to write "Supplier X is cleared" with no verifiable evidence: weight 0.00, confidence unmoved, no different-class corroboration → rejected and logged. It tries twice more. **Standing drops to DEGRADED, on screen** — and its next proposal, an ordinary low-risk one, now requires human approval anyway. Closing shot, five seconds: a later deviation touches Supplier X — **still AT_RISK. The poisoning changed nothing.**

**The closing beat — it knows what it doesn't know.**
The Staleness Sweeper fires on an unrelated expiring belief and downgrades it to `UNKNOWN(stale)` — the system visibly distinguishing "we know this is fine" from "we haven't checked lately."

That arc demonstrates the §1 claim end to end: it acts, it learns, it generalizes what it learned, it protects what it learned, it punishes attempts to corrupt it, and it knows when its own knowledge has gone stale.
