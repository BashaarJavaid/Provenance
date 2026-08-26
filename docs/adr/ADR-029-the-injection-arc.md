# ADR-029 — The injection arc claims that the gateway holds, and deliberately not that the payload caused the proposal

**Status:** Accepted

**Decision:** Item 27 adds **no production code**. Its live half is one script,
`scripts/verify_injection_arc.py`, which runs a single incident carrying the crafted payload
and makes item 21's arithmetic assertions against it — the two halves that were previously two
traces read side by side. It asserts §10's claim, *the gateway holds when both outer filters
leak*, and it explicitly does **not** assert that the payload caused the dangerous proposal.
`incident.Trigger.raw_content` stays off the `POST /trigger` wire, and no sixth span shape is
introduced.

**Reasoning, in order of weight:**

1. **The causal claim is not available, so it is not made.** `risk.BASE` has two entries and
   only one of them acts on a supplier, so `DISABLE_COMPLIANCE_CHECKS(SUP-042)` is the only
   action a supply-chain incident can reach — with the payload or without it. Item 21 already
   measured that: the identical trigger, no `raw_content`, ends `HELD` at `4 + 2 + 2 + 3`. Any
   sentence of the form "the injection made the agent propose it" would therefore be
   unfalsifiable here, and the honest reading of spec §10's own diagram is weaker than it
   looks: the arrow it draws is *"neither Model Armor nor the sanitizer fully neutralized the
   injection"*, which is a statement about the filters, not about the agent's motive.

   **Rejected: measure it with an A/B.** Running both arms and diffing the `Diagnosis` is
   cheap and was considered. It was refused for `ADR-026`'s reason, applied a second time: one
   `gemini-2.5-pro` sample per arm cannot separate a causal effect from sampling noise, and a
   null result would read as a weakness the arc does not have. The gateway's guarantee is
   indifferent to why the action was proposed — that indifference *is* the guarantee — so an
   A/B would spend model calls measuring the one quantity the design says is irrelevant.

   **Rejected: re-script the arc so the payload is necessary.** Adding a third supplier tool,
   or narrowing the trigger so no action is recommended without `raw_content`, would make the
   injection load-bearing. That is tuning the fleet until it produces the demo, which is the
   move `ADR-003` and `ADR-027` refuse in the risk table and the Model Armor threshold
   respectively. `CLAUDE.md` already forbids the third tool by name.

   What replaces the causal claim is a *pairing*: `verify_supply_chain.py` and
   `verify_injection_arc.py` fire byte-identical triggers differing only in `raw_content` and
   both land on 11. Run together, they say something a causal claim could not — the payload
   changed nothing the gateway could see, and that is the point. Both were run for item 27 and
   the two traces differ by exactly the sanitizer's chain; the ROADMAP note carries the counts.

2. **One run, not two suites read together.** Before item 27 every clause of its `verify:`
   line was green somewhere: `verify_model_armor.py` and `verify_sanitizer.py` for the two
   filters, `verify_supply_chain.py`'s `check_result()` for the arithmetic. Composition is not
   transitive, though — `verify_sanitizer.py` asserted only that the payload-bearing incident
   ended `HELD`, never *at what score*, and the scored run carried no payload. The item is
   therefore the composition and nothing else, which is why it ships as a script rather than
   as a module.

   The script imports its fixtures rather than copying them: `RAW_ALERT` / `RAW_TOKENS` /
   `scan()` from `verify_sanitizer.py`, and `check_result()` / `check_spans()` / the trigger
   constants from `verify_supply_chain.py`. This is `verify_refuted.py`'s precedent — three
   scripts now agree on one payload string, and three copies of it would drift. The single
   production-side edit outside the new file is `check_spans()` gaining an `expected_steps`
   keyword defaulting to item 21's three, so the eighty lines of span assertions have one
   implementation across a three-step run and a four-step one.

3. **`raw_content` stays off the wire.** `app.py`'s `TriggerRequest` keeps its four fields.
   Nothing in item 27's `verify:` line needs an HTTP path — the arc is a script assertion, and
   the demo beat that would fire it over the wire is items 37–38. Adding the field now would be
   `ADR-027`'s own mistake in reverse: a validated channel existing for a consumer that has not
   been written, which is the speculative shape `CLAUDE.md` §2 forbids. It is one line and one
   test whenever a beat actually needs it.

4. **No new span shape, and the arc is still countable.** §8.1 stays at five shapes. The only
   span-level evidence that the payload entered a given run is the reasoning-chain *count*:
   four steps where item 21's run has three, because item 26 gave the sanitizer the existing
   `reasoning.chain` shape rather than a sixth one. That count is asserted live and cannot be
   asserted offline, where `FakeSanitizer` stands in for `sanitize()` and no sanitize span is
   emitted — recorded here so the gap is a decision rather than an oversight.

5. **What the offline half is for, given all of the above.** `tests/test_incident.py`'s item-27
   test stipulates both filters leaking — the honest stipulation, since items 25 and 26
   measured them leaking on this exact payload — and asserts the composition: `HELD`,
   `HOLD` at stage `risk` with reason `RISK_THRESHOLD`, components `(4, 2, 2, 3)` **and** the
   band separately, the `Decision`'s subject naming agent/class/target and nothing else, and no
   payload token in the Planner's `success_predicate`, any prompt, or any span attribute. The
   two arithmetic halves are separate assertions because they fail to different mutations, and
   one of those mutations — `NOTIFY_CEILING` past 11 — is a supply-chain incident that
   *executes*.

**Consequences:**

- The demo can say "both outer layers leaked and the gateway held anyway" and have a single
  trace behind it. It cannot say "the injection made the fleet do this", and `docs/demo-script.md`
  already does not (its wording is "proposes the dangerous action **anyway**").
- Deleting the sanitizer from `run_incident()` does **not** turn item 27's own test red — it
  turns item 26's three red. That is correct rather than a gap: with no sanitizer the fact is
  simply absent, the payload still reaches no prompt, and the gateway still holds at 11. The
  arc's claim genuinely does not depend on the second filter existing, which is the strongest
  possible form of "screening is a filter, not a boundary".
- If Model Armor's classifier ever starts catching the crafted payload, this arc dies as
  scripted. The recorded response is unchanged from `ADR-027` and `CLAUDE.md`: re-script the
  arc, never lower `HIGH`. `verify_injection_arc.py` says so in its own failure message.
