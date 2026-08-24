# The second domain cost 114 lines in one agent file, and 417 touched lines everywhere else

**What this is:** ROADMAP item 22 — the count `ARCHITECTURE.md` §5.4 promised and `ADR-024` deferred to. Spec §18 stakes the project's generality claim on a number rather than an adjective, and names the sentence it expects to be able to write:

> "The Supply-Chain domain added *N* lines in one agent file and one registry entry. Zero lines changed in the gateway, the risk table, the Memory Policy Engine, the Sweeper, or the orchestrator."

That sentence is not true of what was built. Item 22's verify line anticipated this — *"if the number isn't small, the control plane isn't general and the spec is wrong — better to find out now"* — so this report leads with the miss rather than arguing around it.

**Baseline.** Item 21 is exactly one commit, `a093bc6`. The merge that landed it, `b4d8a87`, adds nothing. Every number below comes from that one commit and nothing else.

---

## The headline, written true

> The Supply-Chain domain added **114 lines in one agent file** and **zero in a registry entry** — `supply-chain-agent` has been seeded since item 5. Zero lines changed in the gateway, the risk table, the Sweeper, or the Orchestrator. **The Memory Policy Engine changed by 46 touched lines**, 24 of them behavioural. And **417 further lines were touched across nine other modules** — 207 of them behavioural — which §18 did not predict at all.

Two of §18's clauses are wrong, and they are wrong in opposite directions. The registry entry cost *less* than promised (nothing). The control plane cost *more* (one of the five named components moved, and the control loop beside them moved by 160 touched lines).

## §18's five, one by one

| §18 component | File | Touched |
|---|---|---|
| Gateway | `provenance/gateway.py`, `provenance/credentials.py` | **0** |
| Risk table | `provenance/risk.py` | **0** |
| Memory Policy Engine | `provenance/policy.py` | **+34 / −12 = 46** |
| Sweeper | *does not exist yet — Phase 9* | n/a |
| Orchestrator | `provenance/agents/orchestrator.py` | **0** |

The Sweeper row is `n/a` and deliberately not `0`. A component that has not been written cannot be evidence that it did not have to change; counting it as a zero would be inflating the result with a file that does not exist.

**Named beside them, because burying it is what this item exists to prevent — the control loop:**

| | File | Touched |
|---|---|---|
| Graph, routing edge map, state seeding | `provenance/incident.py` | **+118 / −42 = 160** |

`incident.py` is not one of §18's five. `agents/orchestrator.py` — the Orchestrator agent of §5.3, the thing §18 names — really is at zero. But `incident.py` is what builds the graph, sets `ctx.route` and merges the seeders, and 160 touched lines there is the single largest number in this report. Reporting it only as part of an undifferentiated "adaptation cost" total would be technically compliant with §18 and dishonest about what happened.

Also at zero, and listed because `ADR-024` claims it: `action.py`, `tools.py`, `executor.py`, `beliefs.py`, `audit.py`, `registry.py`, `models.py`, `web/index.html`, and `scripts/seed_registry.py`.

## What `policy.py`'s 46 lines are, and are not

The whole of the change is §4.3's decay clock becoming a lookup:

- `HALF_LIFE_DAYS` went from a `float` to a `dict[str, float]` with two keys, both `30.0`.
- A **required** `domain=` keyword was threaded through `contributions()`, `confidence()`, and their one internal call site in `_decide()`.
- `half_life_days` and `expires_at` on the committed version read from the lookup.
- The remaining 22 touched lines are the comment block explaining why both values are equal and why an unpublished domain raises rather than defaulting.

**Unchanged:** §2.2's pipeline and its stage order, both thresholds (`NEW_BELIEF_THRESHOLD`, `FLIP_THRESHOLD`), §6.3's different-source-class rule, `COUNTED_REJECTIONS`, every `CommitReason` and every refusal path, `retract()` and §6.4's gate, the standing counter, the signing.

So the determinism boundary did not move: no decision changed, and the new number is as published and as fixed as the one it replaced. **But the file changed, and §18 said zero.** The honest form of the claim §18 was reaching for is narrower than the one it wrote: *no decision path in the Memory Policy Engine changed* — which is true, and which is a weaker sentence than "zero lines".

## The full count under `provenance/`

Raw, from `git show --numstat a093bc6`, with the two classification columns defined in **Method** below.

| File | + | − | touched | moved | comment | behavioural |
|---|---:|---:|---:|---:|---:|---:|
| `agents/supply_chain.py` — *the domain agent* | 114 | 0 | 114 | 0 | 48 | 66 |
| `incident.py` | 118 | 42 | 160 | 2 | 68 | 90 |
| `agents/sre_infra.py` | 61 | 17 | 78 | 17 | 22 | 39 |
| `policy.py` | 34 | 12 | 46 | 0 | 22 | 24 |
| `synthetic/company.py` | 44 | 2 | 46 | 0 | 30 | 16 |
| `agents/planner.py` | 15 | 18 | 33 | 1 | 8 | 24 |
| `agents/_reasoning.py` | 27 | 0 | 27 | 15 | 12 | 0 |
| `app.py` | 8 | 2 | 10 | 0 | 2 | 8 |
| `recall.py` | 8 | 2 | 10 | 0 | 6 | 4 |
| `telemetry.py` | 6 | 1 | 7 | 0 | 5 | 2 |
| **All of `provenance/`** | **435** | **96** | **531** | **35** | **223** | **273** |
| **Outside the agent file** | **321** | **96** | **417** | **35** | **175** | **207** |

`_reasoning.py` at **zero behavioural lines** is the cleanest row in the table: it received `Diagnosis` unchanged and gained a docstring saying why it now lives there. Nothing was written; something was relocated.

## Method

The adjustments are defined before the number so they are a definition rather than an argument.

1. **A unit is one added-or-deleted line** in `git show --numstat a093bc6`. A rewritten line therefore counts twice — once deleted, once added. This is why "touched" is larger than net growth, which is `+225` outside the agent file. Both are reported; neither is the flattering one by accident.
2. **Moved** — counted by **git's own move detection**, not by hand and not by a bespoke matcher:
   ```
   git show a093bc6 --format= --color-moved=zebra \
       --color-moved-ws=allow-indentation-change -- provenance/
   ```
   It finds three moves, totalling 35 lines: `Diagnosis` from `sre_infra.py` to `_reasoning.py` (15 lines each way), one line of item 20's literal-values clause from `planner.py` to `sre_infra.py`, and one `company.service(trigger.target)` call from `incident.py` to `sre_infra.py`. It does **not** count the rest of item 11.5's predicate floor as moved, and it is right not to: that block was rewritten into an f-string as it moved, so only one line survived byte-identical. Hand-counting it as a move would have shaved about fourteen lines off the result on a judgment call.
3. **Comment** — added or deleted lines that are blank, a `#` comment, or inside a docstring, determined by parsing the pre- and post-image of each file with `ast` and `tokenize` rather than by pattern-matching the diff. Prompt text inside a string literal is **not** comment: it is what the model is told, so it is behaviour. A line that is both moved and a comment is counted once, as moved.
4. **Behavioural** is the remainder. It is not "lines of logic" — it includes signature changes, imports, and call-site threading — it is only "what is left after relocation and prose".
5. **The reconciliation must sum to the raw total.** This is the rule `telemetry.set_risk()` puts on §4.2's four risk components, applied to a diff: if the columns do not add up, the itemization is wrong and the raw number stands.

## The reconciliation

```
Outside the agent file, under provenance/

  raw lines touched (+321 / −96)          417
    less moved (git --color-moved)       − 35
    less comment / docstring / blank     −175
    ─────────────────────────────────────────
  behavioural                             207

  (net line growth, for comparison:      +225)
```

**`ADR-024` estimated "roughly forty changed lines". The measured behavioural figure is 207 — about five times that.** The estimate was written from the list of *files* touched — and it under-counted those too, naming eight where there are nine (`_reasoning.py` is missing from it). Eight modules changed by five lines each is a plausible mental image of a diff that is in fact 160 lines in `incident.py` alone. That sentence in `ADR-024` now points here instead of carrying a number.

## What proving it cost

Reported separately because it is a different claim — §18 asks what the *domain* cost, not what *demonstrating* it cost.

| | + | − |
|---|---:|---:|
| `tests/` (six files) | 381 | 20 |
| `scripts/` (`verify_supply_chain.py` +369, two others +5) | 374 | 2 |
| `docs/` (`ADR-024`, the ADR index) | 31 | 0 |
| `ARCHITECTURE.md`, `CLAUDE.md`, `ROADMAP.md` | 40 | 3 |
| **Total outside `provenance/`** | **826** | **25** |

Whole commit: **+1261 / −121**.

## Is 207 small?

No — not against §18's target of zero, and not against the 114 lines the agent file itself cost. Two readings are available and only one of them is honest.

**The reading this report rejects:** that 207 is the price of adding a domain, and the control plane is therefore 65% overhead. That would be the right reading if item 21 had been the third domain, or the tenth.

**The reading the evidence supports:** item 21 was **one to two**, not *N* to *N+1*, and almost all of the 207 is the cost of discovering which parts of a loop written for one domain were quietly *about* that domain. `ADR-024` names each one, and every one is a single-domain assumption rather than a supply-chain feature:

- `build_graph()` built one domain node and routed `{"ROUTED": domain_agent}` — now nodes and the edge map are comprehended out of `DOMAINS`.
- `_seed_state()` called `company.service()` unconditionally and raised `KeyError` on a supplier — now every domain's `seed_state()` runs and returns its own keys.
- `planner.py` interpolated `{current_config_version}`, `{known_good_version}` and `{nominal_error_rate}` into a prompt used by every incident — now one `{planner_context}` slot the routed domain fills.
- `recall.query_text()` called every target "a … service" in the sentence it embedded.
- `HALF_LIFE_DAYS` was one number for a formula §4.3 publishes as `half_life_domain`.
- `Diagnosis` lived in the SRE agent's file while `incident.hand_off` read it for whichever agent ran.

None of those is work the *next* domain repeats. All of them are work that would have been repeated for every domain forever had item 21 not been the item that found them — which is the actual argument for doing this at two domains rather than asserting generality in a video.

**What this report cannot claim** is that the one-to-two cost predicts the two-to-three cost. That is a prediction, and it is stated as one below rather than as a finding.

## What a third domain predicts

`ADR-024` reason 1 and `ARCHITECTURE.md` §5.4 both claim the *next* domain costs one agent file and one `DOMAINS` entry. Made concrete, so it can fail:

| | Predicted cost |
|---|---|
| `provenance/agents/<domain>.py` | one new file |
| `incident.py` — one import, one 7-line `Domain` entry | **8** |
| `policy.py` — one `HALF_LIFE_DAYS` key | **1** |
| `telemetry.py` — one `TriggerSignal` value, *only if* it introduces a new deviation kind | **0–1** |
| gateway, risk table, Sweeper, orchestrator, executor, beliefs, audit, registry, `planner.py`, `recall.py`, `app.py`, `company.py` | **0** |
| **Total outside the agent file** | **≈ 10** |

**≈10 is the number a third domain has to beat.** A diff materially larger than that falsifies `ADR-024` rather than merely inconveniencing it, and it would mean the generalization item 21 paid 207 lines for did not take. There is no test guarding this — a guard test with one domain to guard is a test of nothing. It gets written when a third domain lands, and this table is what it will assert.

Until then the defensible claim is the narrow one, and it is the one the submission should make: **the second domain cost one agent file, no registry entry, and no change to any decision path in the gateway, the risk table or the Memory Policy Engine — at the price of 207 behavioural lines spent making a single-domain loop multi-domain, itemized above rather than rounded away.**

## Reproduce

```
git show --numstat a093bc6                      # every raw number in this report
git show a093bc6 --format= --color-moved=zebra \
    --color-moved-ws=allow-indentation-change   # the 35 moved lines
```

The comment/behavioural split is derived by parsing each file's pre- and post-image with `ast` and `tokenize` per **Method** rule 3; it is not committed as a script, because rule 2's move detection is git's and rule 3 is twenty lines of `ast.walk` that would need maintaining to be rerun once, when a third domain arrives.
