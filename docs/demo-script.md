# The demo — one continuous incident arc

**What this is:** the demo choreography, lifted verbatim from
[`self-healing-enterprise-project-spec (1).md`](<../self-healing-enterprise-project-spec (1).md>)
§13 so that ROADMAP Phases 12–14 can point at a live document instead of into a frozen
spec. **The §13 beats below are unedited spec text**; this header, the reference table, and
the *As filmed* section at the end are new. Where the build and the spec disagree, the beats
are left alone and the disagreement is recorded — in the two drift notes here, and in the
as-filmed narration that supersedes beat #2.

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

**Two drifts to narrate honestly.** Both are the build disagreeing with the spec, and
both are recorded rather than filmed around.

**Incident #3 — it escalates.** The beat says the class belief fires on `pricing-api` and
the config-deploy hypothesis is prioritized. As built (ROADMAP item 24) the class belief
*is* nominated, survives the currency filter and reaches the agent's prompt before the first
hypothesis — but the incident ends `ESCALATED`, because the executor refuses an action
`pricing-api` cannot receive. That is the generalization beat succeeding and the *execution*
declining, which is a better story than the spec's, not a worse one: the fleet applied what
it learned about a class to an entity it had never seen, and then still would not act
outside what the entity could receive. See `ARCHITECTURE.md` §6.2 and `ADR-026`.

**Incident #2 — the A/B came back negative, and the beat leads with that.** The spec beat
assumes the measurement will flatter the design. It does not.
[`docs/counterfactual-report.md`](./counterfactual-report.md) is titled *"Memory made
incident #2 cost 34% more wall-clock and changed nothing it concluded"*, and every other
metric in the table is identical across the two arms. The reason is a ceiling, not a defect:
`sre_infra.py`'s prompt has carried a config-regression hint since item 9, so the domain
agent reaches the right diagnosis with or without a recalled belief and a metric measuring
the diagnosis has no room to move. **Do not "fix" this by deleting the hint** — item 18
rejected that once and item 32's ROADMAP note rejects it again, with reasons. The as-filmed
narration below replaces the spec's beat rather than softening it.

Two further corrections the spec's beat text gets wrong and the narration must not repeat:
the A/B table reports **model calls**, not tool calls (the fleet makes no tool calls in this
incident), and "hypotheses evaluated before the correct one" is `hypotheses_considered` — a
**model-asserted** number, which is exactly why it is reported as one and never fed to a
deterministic decision.

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
The §10 payload arrives. Model Armor screens it — the crafted payload clears the threshold; the sanitizer reduces it to a fact; the Supply-Chain Agent proposes the dangerous action anyway. We say out loud that both outer layers leaked. The Gateway scores it **11** → held → and the approval card lands in front of the **store operations manager** in plain language. She denies. Separately, the **Supply-Chain Agent** attempts to write "Supplier X is cleared" with no verifiable evidence: weight 0.00, so it corroborates nothing, and a class that cannot move the number cannot overturn a belief → rejected and logged. It tries twice more. **Standing drops to DEGRADED, on the registry panel, on screen** — three rows hold GOOD while one flips, with the three reasons that earned it. Its next memory write, this one well-evidenced, is refused outright. Then we show the other half of what DEGRADED means on a **second** agent — the Remediation Planner, degraded by hand — whose ordinary `ROLLBACK_CONFIG` scores a boring **2** and is held for a human anyway. Say the split out loud: no agent in the registry both writes beliefs and holds a tool scope, so this takes two of them rather than one (`docs/adr/ADR-030`). Closing shot, five seconds: a later deviation touches Supplier X — **still AT_RISK. The poisoning changed nothing.**

**The closing beat — it knows what it doesn't know.**
The Staleness Sweeper fires on an unrelated expiring belief and downgrades it to `UNKNOWN(stale)` — the system visibly distinguishing "we know this is fine" from "we haven't checked lately."

That arc demonstrates the §1 claim end to end: it acts, it learns, it generalizes what it learned, it protects what it learned, it punishes attempts to corrupt it, and it knows when its own knowledge has gone stale.

---

## As filmed — what replaces beat #2, and the shot list

The section above is frozen spec text. This section is what the camera actually does.

### Beat #2, as narrated

> "The obvious claim here is that memory makes the fleet faster. We measured it, and it
> doesn't. Twelve live incidents, six of them measured: with recall on, this incident took
> thirty-four percent more wall-clock, and every other number — model calls, hypotheses,
> the diagnosis, the verdict, the committed confidence — came back identical. Recall is a
> Firestore read, an embedding call and a longer prompt, all on the critical path, and on
> this fixture it buys nothing back. The reason is that the domain agent's prompt already
> contains the hint that makes this diagnosis reachable, so there was never any room for
> memory to move the number. We left the hint in and published the negative result, because
> the claim this project actually makes about memory is that belief becomes *governed and
> inspectable* — not that one incident gets faster. That claim is the next thirty seconds."

Then cut to incident #3. The negative result is the setup for the generalization beat, which
is where memory does something nothing else in the system can do.

**On screen for those twenty seconds:** the counterfactual panel and nothing else. It serves
a committed artifact rather than re-running, so it paints instantly and shows the same
numbers on every take. Do not attempt a live A/B — a sixty-second two-arm run is the single
most failure-prone thing a demo can contain, and re-recording the measurement would overwrite
the committed evidence the report's prose describes.

### Shot list

Total 3:40. The rules evaluate the first 4:00, so the closing claim must land before 3:40,
not at it.

| # | Beat | Budget | On screen | Live or pre-triggered |
|---|---|---|---|---|
| 1 | Cold open — the claim | 0:15 | The claim, over the architecture diagram | — |
| 2 | Incident #1, the fleet acts | 0:40 | Trigger strip → live fleet view filling → gateway ledger → the written belief | **Live.** Press the trigger on camera; narrate over the ~60s run |
| 3 | Incident #2, measured not asserted | 0:20 | Counterfactual panel only | Committed artifact — instant |
| 4 | Incident #3, the fleet generalizes | 0:30 | The trace showing the class belief reaching the prompt on a never-seen entity, then `ESCALATED` | **Pre-triggered.** Have the completed trace on screen |
| 5 | The attack, twice | 1:00 | Injection → gateway holds → approval card → deny; then the poisoning attempt → registry panel flipping to `DEGRADED` → the closing `SUP-042` shot | **Mixed.** Incidents pre-triggered; the *deny* and the registry refresh are live and instant |
| 6 | It knows what it doesn't know | 0:20 | Sweeper downgrading a belief to `UNKNOWN(stale)` | Pre-arranged scratch belief |
| 7 | Google Cloud proof shot | 0:15 | Cloud Run console: the service, `--max-instances=1`, the live URL; Vertex logs if time allows | Live console — **mandatory**, budgeted, not squeezed into a corner |
| 8 | Closing claim | 0:20 | Back to the claim | — |

Three incidents cannot be filmed live inside 3:40 — each is roughly a minute of sequential
`gemini-2.5-pro` calls. Beat 2 is the one that earns the live take, because it is the beat
where "filmed live and unedited" is worth the seconds; the rest show completed traces, which
is what a trace panel is *for*.

### Before each take

- **Warm the instance.** `min-instances=0` means the first request pays a cold start. Hit
  `/health` before rolling so the trigger press is the only latency on camera.
- **Reset the fixture** with `scripts/seed_firestore.py --reset` — incident #1 heals the world
  it started from, so a second take without a reset runs against an already-rolled-back service.
- **Clear the approval queue after the deny beat.** A denial leaves a `DENIED` record, and
  `verify_approval_queue.py` refuses to start on a non-empty queue. Delete it deliberately; the
  durable record of the verdict is the `authorizations/` ledger row, which that does not touch.
- **Do not touch `SUP-042`'s chain or `belief-service.tier2`.** They are permanent demo state
  and the closing shot is that two attacks left them byte-identical. `seed_belief.py` has no
  `--reset` and must not grow one.
- **One tab.** The service runs at `--max-instances=1` and the trace panel's span buffer is
  in-process; a second tab triggering an incident lands on the same instance and interleaves.
- **Zoom to 125–150%** for the three close-ups that carry numbers: the risk arithmetic on the
  approval card, the registry panel's standing column, and the belief object's computed
  confidence and evidence IDs. At 100% these are unreadable at video bitrates, and they are
  the shots the architecture argument rests on.
- Hard-reloading between takes is no longer required — `GET /` sends `Cache-Control: no-store`
  as of the revision deployed 2026-08-27.

