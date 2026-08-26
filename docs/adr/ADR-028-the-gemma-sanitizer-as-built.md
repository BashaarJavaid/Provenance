# ADR-028 — The sanitizer is a serverless Gemma call with a strict parser, not a deployed endpoint with a schema

**Status:** Accepted

**Context:** [`ADR-006`](./ADR-006-gemma-sanitizer-isolation.md) decided *that* untrusted content is reduced to typed facts by an isolated Gemma model, and its reasoning is unchanged by this ADR. What it also specified — "Gemma 4 (E4B/12B, served via Vertex AI Model Garden)" — was written at design time and never probed. ROADMAP item 26 probed it, and three of the four findings changed the build. This ADR records what the item decided as a result; `ARCHITECTURE.md` §5.2's as-built block carries the constants, and the ROADMAP item-26 note carries the live evidence.

**Decision:** the sanitizer is `provenance/sanitizer.py`: one `google.genai` call to **`gemma-4-26b-a4b-it-maas`** on the `global` endpoint, retried only on 429, with a strict hand-written parser as the type guarantee. It holds no registry record, emits a `provenance.reasoning.chain` span, and raises rather than returning anything permissive. `incident.run_incident()` calls it as a plain step before the incident span opens.

---

## 1. Serverless Gemma, not a deployed endpoint — the cost ceiling decided this

`ADR-006`'s E4B/12B are Model Garden models you deploy to a dedicated Vertex endpoint, which bills **by the hour whether or not it serves a request**. `CLAUDE.md`'s cost ceiling names that as the single largest threat to the $300 credit — order $1–4/hr, the whole credit in under two weeks of being left up — and prescribes a deploy-only-while-recording discipline with an undeploy step and a standing live trap.

The probe found `publishers/google/models/gemma-4-26b-a4b-it-maas` serving on this project. It is Model-as-a-Service: **no endpoint, no idle billing, nothing to undeploy, nothing to leave running overnight.** It bills per token, at one call per incident that carries raw content.

So the whole apparatus ADR-006 implied — `deploy_gemma.sh`, `undeploy_gemma.sh`, a live trap in `CLAUDE.md`, a setup step before every rehearsal — does not get built, and the trap that was already written down gets **deleted**. This is the rare case where the probe made the item smaller.

It also reuses infrastructure that already exists. `_default_client()` is the construction `recall._vertex_embed()` already makes, `models.LOCATION` is already `global`, and `google-genai` already arrives via `google-adk` — so **`pyproject.toml` is untouched** and the Cloud Run image gains nothing. Contrast item 25, which had to add `google-cloud-modelarmor` and run a dependency regression to prove it moved no ADK pin.

**Alternatives rejected.** *Deploy `gemma-3-1b-it` / `gemma-4-31b-it` to a dedicated endpoint* — strictly worse on cost with no correctness gain, and ADR-006's own "Revisit when" clause is about extraction quality, which the MaaS model meets. *A MaaS-with-dedicated-fallback path* — removes the 429 risk in §2 below, but reintroduces idle billing and adds a second code path to the one module whose whole value is being small and isolated.

**Consequence, disclosed:** the model is `PUBLIC_PREVIEW` and global-only. A regional call answers `FAILED_PRECONDITION`, so `LOCATION` is not a tuning knob here, and preview capacity is what §2 is about.

## 2. 429 is capacity, so it is retried; everything else halts on the first call

The probe measured `429 "The request queue is full."` on roughly **one call in two** — shared preview capacity, not a verdict about the content. Every probe cleared inside two attempts.

A single un-retried call would give any demo take or verify run a coin-flip chance of dying on a transient queue. An unbounded retry is the loop `CLAUDE.md`'s cost ceiling explicitly says is the real risk ("token spend is not the risk; loops are"). So: `SANITIZE_ATTEMPTS = 4` with exponential backoff, on 429 **only**, then `SanitizerUnavailable` — which is §7.3's "ingest halts" and `ingest.ScreeningUnavailable`'s exact shape.

Everything else raises on the **first** call, and that includes a malformed extraction. Retrying a bad shape is not a retry; it is resampling a model until it gives an answer you can use, which would quietly turn `SANITIZE_ATTEMPTS` into an extraction budget. `tests/test_sanitizer.py` asserts the call count in both directions so neither drifts.

## 3. The parser is the type guarantee, because `responseSchema` is ignored

Every other reasoning component here gets its shape structurally, from an ADK `output_schema` that compiles to Vertex's `responseSchema` — §5.5 calls that "structural, not instructed", and it is why a Planner cannot answer in prose.

**Gemma ignores it.** Probed with a two-field schema, the model returned a JSON object carrying one invented field and neither declared one. So the structural guarantee is simply not available on this model, and `sanitizer._parse()` is the entire meaning of "typed facts": strip the fence Gemma adds about half the time, `json.loads`, then refuse anything whose keys are not exactly `FIELDS`, whose `statement`/`subject` are not non-empty strings, or whose `pii_tokens` is not a list of placeholders. Every refusal is `SanitizerUnavailable`; there is no partial fact.

This is the correct side of §4.1 regardless. The model's role ends at *extraction*; deciding whether what came back is usable is code's job, and putting it in code is what makes the fifteen failure modes in `tests/test_sanitizer.py` checkable offline.

**`responseSchema` is not sent at all.** Sending config that is silently ignored would read, to the next person, as if it were the guarantee — which is exactly the confusion this ADR exists to prevent. A comment saying "the parser is the guarantee" beside config implying otherwise is worse than no config.

**Alternative rejected:** *wrap it as an ADK `LlmAgent` with `output_schema`*, matching the other five agents. It would look like a structural guarantee and not be one. It also gives the sanitizer an agent's shape when §5.2's entire claim is that it holds no tools and no authority.

## 4. The PII placeholder rule — found by running it, not by designing it

The first live run of `scripts/verify_sanitizer.py` **failed**, and the failure is the most useful thing item 26 produced.

Told to "list every token you used", Gemma tokenized the statement correctly — `[PERSON_1]`, `[EMAIL_1]`, `[PHONE_1]` — and then listed, in `pii_tokens`, the *values it had replaced*: a name, an email address and a phone number, verbatim. The one field whose job was to prove the PII had been removed was the field carrying it. It travelled into the seeded prompt state and out onto ADK's own `call_llm` spans from there, and the verify script caught all nine leaks.

Two changes, at two layers, because one of them is not enough:

1. The prompt now says to list the placeholders and never the values, with an example.
2. `PLACEHOLDER` — `^\[[A-Z][A-Z0-9_]*_\d+\]$` — is enforced in `_parse()`. A token that is not a placeholder **is** PII, and PII is the one thing this module exists to stop.

The prompt fix alone would have been the system prompt used as a security boundary, which `ADR-006` rejects in its first line. The refusal message names a count and never the values: quoting them would move the leak into logs rather than close it. This is the same lesson as §5.5's predicate floor (item 11.5) — the fix goes upstream into code, not into a looser check downstream.

## 5. No registry record, no sixth span shape, no new incident outcome

**No registry record**, on the Verification Agent's precedent (§5.8): it proposes no action and writes no belief, so §3.4 has nothing to record about it. Its spans carry `sanitizer@v1` the way that agent's carry `verification-agent@v1`. Adding one would mean editing `scripts/seed_registry.py`, which has no `--reset` and is a live trap, to assert an authority the component does not have.

**No sixth span shape.** §8.1 gives `provenance.reasoning.chain`'s owner as "any **[LLM]** component", which the sanitizer is; `step` was already a free `str`, so `"sanitize"` cost no vocabulary change and no `tests/test_telemetry_schema.py` change. Five shapes, and the streak since item 16 holds. Emitting *nothing* — item 25's choice for Model Armor — was rejected: that is a managed service filtering, this is our own model call, and item 26's `verify:` line is phrased about the trace, so the trace should show it ran. It does, countably: the live run shows four reasoning steps where item 21's shows three.

**No new `IncidentOutcome`.** §7.3 says ingest *halts*, not that the incident ends with an outcome. Screening and sanitizing happen before the incident span opens, so a halt leaves no incident id, no span and no record — `ingest.ContentBlocked` or `SanitizerUnavailable` propagates out of `run_incident()`. A `HALTED` outcome would have cost the telemetry vocabulary, an §8.1 amendment and a schema test, to assert that a reasoning loop ran when none did. Reusing `UNROUTABLE` was rejected outright: that means the Orchestrator could not classify a deviation, and conflating the two makes the trace lie.

## 6. Where it is called, and what carries the content

A **plain step in `run_incident()`**, before the span, on `recall`'s precedent (§5.3: "still called from `incident.py` as a plain step rather than a graph node"). The graph stays the graph, so ADR-007's park/resume and item 20's re-plan edge are untouched by an ingest concern.

The content arrives on `Trigger.raw_content`, and the fact leaves on a **shared** `sanitized_facts` state key. Shared rather than per-domain because an untrusted inbound report is not a supply-chain fact: one line in each domain agent's instruction keeps §5.4's generality claim and [`docs/generality-report.md`](../generality-report.md)'s ≈10-line prediction unmoved, and a third domain gets the channel for free. `SanitizedFact` is not a fifth §3 object, on `incident.Trigger`'s own reasoning — §3's shapes carry authority-relevant data and this carries the least authoritative thing in the system.

`POST /trigger` is **not** given the field. Nothing over HTTP needs it until item 27 drives the demo, and a public field ahead of its caller is the shape `CLAUDE.md` §2 forbids — the same reasoning that kept `screen()` uncalled through item 25, recorded in [`ADR-027`](./ADR-027-model-armor-on-ingest.md).

**Revisit when:** extraction quality on real inbound formats proves insufficient (ADR-006's clause, unchanged), or `gemma-4-26b-a4b-it-maas` leaves `PUBLIC_PREVIEW` — at which point the 429 rate should be re-measured and `SANITIZE_ATTEMPTS` reconsidered, downward.
