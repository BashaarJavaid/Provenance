# ADR-034 — The counterfactual A/B ablates recall alone, counts model calls where the item said tool calls, and is served as a committed measurement rather than run on demand

**Status:** Accepted

**Decision:** Item 32's A/B runs incident #2 twice per trial under one variable —
`run_incident(memory=...)`, which skips `recall.recall()` and changes nothing else. Three
trials per arm, interleaved, medians reported. Each trial is a *pair* of incidents, because
incident #2's premise is a belief already in the store: a cold incident #1 seeds v1, the
service fixture is put back, and the second incident is the measured one. The metrics are
**wall-clock** (measured around `run_incident()` in the runner), **model calls** (item 32's
new `provenance.reasoning.model_calls` attribute), **input/output tokens** (on the reasoning
span since item 9), and **hypotheses considered** (the model's own integer, labelled as such).
The result is committed as per-run JSON in `docs/counterfactual/`, derived into
`provenance/web/counterfactual.json`, served by `GET /counterfactual`, and rendered as §8.2's
sixth and final surface. `scripts/verify_counterfactual.py` with no arguments re-derives the
table from the run artifacts and refuses if any copy of it disagrees.

The numbers themselves live in [`docs/counterfactual-report.md`](../counterfactual-report.md)
and are not restated here.

**Reasoning, in order of weight:**

1. **The item names four metrics and this architecture has three of them; saying so is the
   first job (primary reason).** "Tool calls" counts something that does not exist here. No
   agent is built with `tools=` — all six are output-schema-constrained `LlmAgent`s — and
   `provenance/tools.py` is a declarative action-class table ([`ADR-011`](./ADR-011-tool-registry-and-action-validation.md)),
   not an ADK tool registry. The honest substitute is **model calls**: requests, which is what
   "tool calls" was reaching for as a proxy for work done. Rejected: silently reporting zero
   (true, and useless), and dropping the row (the demo script and §8.2 both name it, and a
   missing row reads as an oversight rather than a finding). The report says the metric does
   not apply and what replaced it, because a table that quietly renames a column is worse than
   one that explains itself.

2. **"Hypotheses evaluated before the correct one" is not derivable, and the near miss is a
   model's self-report.** Nothing stores an ordering. `hypotheses_considered` is an integer the
   agent asserts about its own reasoning, and it has been telemetry-only since item 9 for
   exactly this reason (`_reasoning.py`'s docstring: *"a model inflating its own hypothesis
   count changes a chart, never a decision"*). Reporting it is fine — §1.1 property 3 forbids
   a model-asserted number being an **input to a deterministic decision**, and no decision
   reads this one. Reporting it *unlabelled* is not fine, so the panel and the report both
   carry "model-asserted" beside it. Rejected: adding a `hypotheses: list[str]` field to the
   canonical `Diagnosis` object — a longer self-report is still a self-report, and §3's typed
   objects do not get reshaped to improve a chart.

3. **The ablation moves one variable, so the disabled arm still commits.** `memory=False`
   disables *reading* memory. The belief is present in both arms, and §2.2's commit runs in
   both — both end at v2, which `tests/test_counterfactual.py` asserts per arm. Rejected:
   also skipping the commit ("a fleet with no memory subsystem"), which would leave the table
   unable to attribute its own delta to recall; and running the disabled arm against an empty
   store, which is not a control at all but incident #1, an incident that already exists and is
   already measured.

4. **The switch is a keyword argument on the shipped function, not a patch applied by the
   runner.** `verify_counterfactual.py` could have monkeypatched `recall.recall` and touched
   nothing under `provenance/` — item 18's and item 8's posture, and tempting for the same
   reason. It is refused here because the measured path would then not be the shipped path:
   the arm under test would be a module the deployment does not contain. Three lines and a
   ternary is a smaller lie than a patched import. The default is pinned by a test that reads
   the signature directly, since the suite's own helper forwards the flag and so cannot see a
   change to it.

5. **The panel serves a committed file, and the route runs nothing.** A `GET /counterfactual`
   that executed the A/B on request would spend twelve real incidents of Gemini per click —
   the cost-ceiling trap `CLAUDE.md` names — and would answer a different number every time,
   which is not what "reproducible from the committed run artifacts" means. Rejected also:
   typing the numbers into `index.html`, which is the smallest diff and produces exactly the
   drift [`ADR-021`](./ADR-021-the-belief-inspector.md) reason 3 refused for the belief
   breakdown. Three renderings exist by necessity — the raw runs, the served JSON, the
   markdown a reader sees — and only the first is evidence; the script asserts the other two
   are renderings *of it*.

6. **The served table lives under `provenance/` rather than beside its evidence.** The
   Dockerfile copies `pyproject.toml` and `provenance/`, so a route reading `docs/` works on a
   laptop and 404s in the image. The raw runs stay in `docs/counterfactual/` where a reader
   looks for them, and the derivation between the two is checked rather than trusted.

7. **Three runs per arm, interleaved, median rather than mean.** One run per arm cannot tell a
   difference from a slow afternoon, and this table is what three ADRs defer their causation
   claims to. Interleaved on/off/on/off so that drift in Vertex latency across the session
   lands on both arms; median rather than mean because a single 429-and-retry would move a
   mean of three and move a median of three not at all. Rejected: five per arm — twenty
   incidents for a tighter median on a measurement whose stated limits are qualitative, not
   statistical.

8. **No `provenance.incident.memory_enabled` attribute, so a trace cannot name its own arm.**
   The disabled arm's spans carry an empty `provenance.recall.belief_ids`, which is exactly
   what a cold incident #1 produces — so the trace alone cannot distinguish "memory disabled"
   from "memory found nothing". The run artifact records which arm each trace id belongs to,
   and the report states the limitation rather than adding a second §8.1 vocabulary change in
   a commit that already makes one. Revisit when: anything other than this script needs to
   read an arm off a trace.

9. **The model-call count is incremented before the usage check, not with it.** A response
   that arrives without `usage_metadata` still cost a request. Folded into the token guard,
   the counter would under-report precisely the responses whose tokens are already missing —
   so whichever arm happened to draw more of them would look cheaper, and the A/B would be
   measuring Vertex's reporting rather than the fleet's work. The sanitizer's `_call` returns
   its attempt count for the same reason: it retries on `429` up to `SANITIZE_ATTEMPTS` and a
   constant 1 there would be wrong more often than right ([`ADR-028`](./ADR-028-the-gemma-sanitizer-as-built.md) §1).

10. **What the table does not claim.** It measures what a run *cost* under two conditions. It
    does not show that memory caused a better diagnosis, and cannot: `sre_infra.py` carries its
    own config-regression hint in both arms, and item 18 rejected removing it because incident
    #1 is a cold case that would lose its only hint. [`ADR-026`](./ADR-026-incident-three-and-the-cold-entity.md)
    §5 and item 24's note both point here for "the number"; the number they get is a cost
    delta, and the report leads with that rather than letting a reader infer more.

**Revisit when:** a domain agent gains real tools, at which point "tool calls" becomes a
countable thing and reason 1 is obsolete rather than answered; or the fleet gains a second
measured incident, at which point one table with an incident column beats two panels.
