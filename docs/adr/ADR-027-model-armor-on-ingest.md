# ADR-027 — Model Armor is one template, logged by the service itself, and not yet wired to anything

**Status:** Accepted

**Decision:** Ingest screening is a single Model Armor template — `provenance-ingest` in
`us-central1`, prompt-injection/jailbreak enforcement at **HIGH** confidence plus Sensitive
Data Protection **basic** — whose verdicts are written to Cloud Logging by **Model Armor
itself** (`log_sanitize_operations`), not by our code. `provenance/ingest.py` wraps one call
and fails closed. It emits no span, and **nothing calls it yet**.

**Reasoning, in order of weight:**

1. **The module is built ahead of its caller by exactly one item, because there is no ingest to
   wire it to.** Item 25's title says "wired on all ingest", but this repo has no untrusted
   free-text ingest: `incident.Trigger` is a validated entity id, a `Literal` signal, a float
   and a timestamp, and every string that reaches a prompt comes from the frozen entity model
   in `provenance/synthetic/company.py` or from our own agents. The untrusted-content path is
   item 26's (the Gemma sanitizer) and its consumer is item 27's (the injection arc). Adding a
   `raw_content` field now would be a field nothing reads for a whole item — the speculative
   shape `CLAUDE.md` §2 forbids. What item 25 *can* do honestly is build the mechanism and
   prove it live, which is what its `verify:` line actually asks for: two payloads, two
   verdicts, one of them in Cloud Logging. No incident has to run for that to be checkable.
2. **HIGH confidence is a prior commitment, not a fitted threshold.** Spec §10 published
   "clears the HIGH-confidence threshold" long before anyone measured this payload against
   this service. Choosing the level *after* seeing a result would be tuning the instrument to
   the answer, which this repo refuses everywhere else — the risk table is a lookup, confidence
   is a published formula, and `ADR-003` rules out ML scoring precisely so numbers cannot be
   nudged. So the level was fixed first and then measured. It happens to have come out the way
   §10 predicted (blunt blocked on `pi_and_jailbreak`, §10's crafted payload clears); had it
   not, the recorded fix was to re-script item 27 and correct `THREAT_MODEL.md`, never to lower
   the number. `scripts/verify_model_armor.py` says so in the failure message itself.
3. **The verdict log is the service's record, not our restatement of it.** One flag on the
   template and Model Armor writes every verdict under
   `modelarmor.googleapis.com/SanitizeOperation`, carrying the filter match state, the
   confidence level and its own verdict reason. Writing our own log line beside it would create
   two sources that can disagree about the same event — the failure mode this repo designs
   against elsewhere (`superseded_by` is derived rather than stored, §4.3 has exactly one
   implementation). It also keeps `google-cloud-logging` out of the image, which `ARCHITECTURE.md`
   §8.1's dependency comment deliberately excluded.
4. **No sixth span shape.** Item 25 says verdicts are *logged*; it never says traced. §5.1 is
   explicit that Model Armor is "the first filter — never the boundary", so it is not one of
   the decisions the architecture makes and does not get a decision span. The five shapes and
   §8.1's attribute vocabulary are untouched. This also keeps a promise cheap: item 26's
   `verify:` line is that raw inbound text never appears in the trace, and the surest way to
   keep it is for the screening path to put nothing there at all.
5. **Fail closed, because a filter that is down must not look like a filter that passed.**
   §7.3's row reads "Model Armor or sanitizer unavailable → ingest halts". So `screen()` raises
   `ScreeningUnavailable` on any API error, on `invocation_result=FAILURE` (the service
   answered but says it did not screen), and on a missing project — and never returns
   `Verdict | None`, the same structural rule `registry.py`, `beliefs.py` and `recall.py`
   follow. `tests/test_ingest.py::test_an_unreachable_service_is_not_a_clean_pass` is the case
   the module exists to get right.
6. **A `Verdict` carries filter names and nothing else.** This is the one object in the repo
   that has held raw untrusted content, so it holds §8.1's redaction line even though it never
   reaches a span. Worth being precise about the limit: the *log entry* does contain the
   screened text, because `log_sanitize_operations` makes Model Armor record its own input.
   That is the managed service's behaviour and it is disclosed in `THREAT_MODEL.md` rather than
   left for someone to discover.

**Overtaken by item 26: `screen()` has a caller.** The template, the HIGH level and the service's own verdict log are unchanged — what expired is the last clause of the Decision above. `incident.py` screens `Trigger.raw_content` before anything reads it and raises `ingest.ContentBlocked` on a match, and what clears the filter goes to the Gemma sanitizer ([`ADR-028`](./ADR-028-the-gemma-sanitizer-as-built.md)). "Wired on all ingest" is now a claim this repo can make; item 27 is the arc that shows the outer layer leaking anyway.

**Alternatives considered:**

- **Model Armor as the boundary.** Rejected before this ADR existed — `ADR-006` and spec §10
  both state it, and the demo is built around it leaking. Recorded here only because a template
  at HIGH confidence looks like a boundary if you do not read the surrounding documents.
- **`MEDIUM_AND_ABOVE` confidence.** Stricter and arguably the better production default, but it
  raises the odds of catching the crafted payload, and the threshold was already published. If
  a production posture is ever wanted, that is a second template, not a change to this one.
- **The DLP (Sensitive Data Protection) API directly.** More granular than SDP basic and needs
  an inspect template to keep in sync. Item 25 names SDP as one of two filters on one template;
  advanced config is the upgrade path if `ADR-006`'s tokenization needs it.
- **Regex or rule-based screening.** `ADR-006` already rejected this for the sanitizer's job.
  It fails harder here: the track brief names Model Armor, and a hand-rolled classifier would
  be both weaker and something we would have to defend as a security control.
- **`google-cloud-logging` as an explicit writer.** See reason 3.
- **Adding a `raw_content` field to `TriggerRequest` now.** See reason 1.
- **Screening the existing trigger body.** Literally "all ingest" as it exists today, but the
  body is a validated entity id, an enum, a float and a timestamp. Screening them proves
  nothing and would make the item's `verify:` line unreachable.

**Known limit, dated:** the filter version this template resolves to is `v1`, and Model Armor's
own log entries carry a warning that v1 moves to `LEGACY` on **2026-09-01** — after the Aug 31
deadline but inside the Oct 1 judging window. The client library at `0.7.1` exposes no
filter-version knob, so this is not something the template can pin from here. The recorded
demo is unaffected; a judge re-running `scripts/verify_model_armor.py` in September could in
principle see a different verdict on the crafted payload, and the script's failure message
already says what to do about that.

**Revisit when:** a second untrusted-content path appears that `Trigger.raw_content` does not
cover, or the crafted payload starts matching at HIGH — in which case item 27 is re-scripted
and `THREAT_MODEL.md` corrected, never the level lowered.
