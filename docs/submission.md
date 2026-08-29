# Submission — track requirements, bonus points, logistics

**What this is:** the hackathon-facing material, lifted verbatim from
[`self-healing-enterprise-project-spec (1).md`](<../self-healing-enterprise-project-spec (1).md>)
§4 and §21 so ROADMAP Phases 12–14 point at a live document rather than into a frozen
spec. **Both sections below are unedited spec text**; only the headers and the notes
marked *(as built)* are new.

Hard deadline: **August 31, 2026, 5:00 PM PDT**. The hosted URL and credentials must stay
valid through **October 1** for judging. Demo choreography: [`demo-script.md`](./demo-script.md).

---

## 4. Why this fits the track

The Fortified Enterprise Fleet track asks for a scalable network of institutional agents with an Agent Registry, asynchronous long-running operation, secure retained context, per-agent identity/permissions, a controlled data gateway, defense against prompt injection / tool poisoning / PII leakage, auditable telemetry, and production-like operation under real security and compliance constraints.

Judging weights: 40% Innovation & Operational Utility, 30% Architectural Discipline & Tech Stack, 30% Demo & Production Readiness.

| Requirement | How this project addresses it |
|---|---|
| Agent Registry | A live, load-bearing registry (§9): identity, version, declared tool scope, per-domain memory authority, and a **standing score** the gateway and Memory Policy Engine both read on every request. Not a manifest — a runtime authorization input. Demonstrated by a denial that happens *because of a registry entry* |
| Runtime (async, long-running) | Two distinct async behaviours: wake-on-event incident handling against a live stream, and a long-running **Staleness Sweeper** (§8.6) that downgrades expiring beliefs to `UNKNOWN` on a 300s tick — continuous in the process, and honestly bounded by `--min-instances=0`, which is a cost posture rather than an oversight. Plus incidents that park for minutes awaiting human approval and then resume |
| Memory Bank | Versioned institutional belief store — provenance, typed evidence, **computed** confidence, scheduled decay, supersession chain, and first-class retraction |
| Agent Identity | PortunusMCP identity broker — short-lived per-agent credentials, no shared service accounts (pre-existing; see §17) |
| Agent Gateway | PortunusMCP zero-trust gateway — RBAC/ABAC, **deterministic** risk scoring, ECDSA-signed audit log. Architecturally the only path from any agent to a state-mutating action (pre-existing; see §17) |
| Injection / tool-poisoning defense | Layered and honestly framed (§10): **Model Armor** — the guardrail the track brief names — screens all inbound content for injection/jailbreak, and a Gemma-based sanitizer reduces what passes to typed facts. Neither is the boundary. The boundary is the gateway, and the demo shows the outer layers leaking and the inner one holding |
| PII handling | Model Armor's Sensitive Data Protection screens 150+ PII infoTypes at ingest; the sanitizer tokenizes what remains; memory beliefs reference entity IDs, never raw personal data |
| Observability | Every component emits OpenTelemetry-compliant spans (trace IDs, reasoning-chain traces) to a single stream from day one — the UI, the audit log, and the counterfactual metrics all read the same stream. Matches the track's "OpenTelemetry-compliant audit logs" wording literally |
| Production-like operation | Deployed on Cloud Run from phase 1, running against a small, internally consistent synthetic company built on Google's own ADK reference data |
| "Unlikely Hero" (stated judging criterion) | The human in the loop is not an engineer. Every HOLD lands as a plain-language approval card — what the fleet wants to do, why, and the risk arithmetic — in front of a **store operations manager** at the retailer (§12, §13). The risk table's explainability is precisely what makes non-technical governance possible |

*(as built)* The registry row's "§9" is now `ARCHITECTURE.md` §3.4; the Sweeper's "§8.6" is
§6.5; "§10" is §5.1 plus [`THREAT_MODEL.md`](../THREAT_MODEL.md); "§12, §13" are §9 and
[`demo-script.md`](./demo-script.md); "§17" is `README.md`'s pre-existing-code disclosure.

*(as built)* Two rows have narrower true forms than written, both recorded rather than
softened. **Agent Identity / Agent Gateway:** PortunusMCP's own identity broker, risk
engine and policy engine are **not** used — it is consumed as a library for `signing`,
`abac` and `decision` only, and identity resolution, credential minting, the risk table
and the hold/resume path are new code here (`ADR-004`, `ADR-012`, and `README.md`'s
disclosure table). **Injection defense:** Model Armor screens every
inbound payload at `HIGH` (item 25) and the item-26 sanitizer is its consumer — what clears the
filter is reduced to typed facts by an isolated open model before any frontier model sees it.

*(as built)* **The rules' mandatory model requirement is met by `gemini-3.5-flash` on Vertex
AI** — it is the verification judge on every incident, so every run a judge triggers exercises
it. The four reasoning roles run GA `gemini-2.5-pro` because the 3.x line has no GA Pro tier,
and a preview model can change or be withdrawn inside the October 1 judging window (`ROADMAP.md`
item 1's deviation note has the catalog probe behind that). Stage One is pass/fail on a skim, so
`README.md`'s tech-stack table leads with the verification row rather than letting a 2.5 be the
first model a judge sees.

---

## 21. Bonus points and submission logistics

Stage-three scoring adds up to **1.0 point on a 5-point base scale** — blog post (+0.2), social post (+0.2), and +0.2 per additional Google AI model integrated (max +0.6). In a tight field this is the margin. All three are planned work, not afterthoughts:

- **Blog post (+0.2).** §7 — the determinism boundary — already *is* a blog post. Publish it on dev.to or Medium with the required disclosure line ("created for the purposes of entering this hackathon"), and embed the full unedited A/B run from Incident #2 as the artifact the video only summarizes.
- **Social post (+0.2).** X or LinkedIn with **#AllThingsAgenticHackathon**, linking the video and repo.
- **Additional Google AI model (+0.2).** Gemma 4 is the sanitizer (§14) — an integration that strengthens the security story rather than decorating it. No forced Veo/Lyria integrations: one honest model beats three ornamental ones, and judges can smell the difference.

Submission checklist beyond the video:

- **Hosted URL.** Judges may test the project any time through October 1 and are "highly encouraged" to be given one. The Cloud Run UI must work for a cold visitor — approval queue included — with credentials and step-by-step testing instructions in the README.
- **Repo.** Architecture diagram, reproducible spin-up instructions in the README; if private, shared with testing@devpost.com and cloudhackathons@google.com.
- **Video.** Publicly visible on YouTube or Vimeo, hard-capped at 4:00 evaluated (we target 3:40, §13), with the on-screen Google Cloud proof shot (§13) — the rules name the Cloud Run dashboard and Vertex logs as acceptable evidence.
- **Disclosure.** The §17 pre-existing-code table goes in the submission text verbatim.

*(as built)* "§7" is `ARCHITECTURE.md` §4; "§14" is `README.md`'s tech-stack table; "§13"
is [`demo-script.md`](./demo-script.md); "§17" is `README.md`'s pre-existing-code
disclosure. These four bullets are ROADMAP items 33–36 and 38.

*(as built)* The three pieces of writing those bullets call for are drafted, unpublished, and
live one to a file: [`devpost-draft.md`](./devpost-draft.md) (item 35),
[`blog-draft.md`](./blog-draft.md) (item 33), [`social-draft.md`](./social-draft.md) (item 34).
Publishing is the human half of each item's `verify:` line and none of the three is done until
its public URL exists. The bonus arithmetic above is unchanged by them; what changed since the
spec wrote it is that **four** Google AI models are integrated rather than the one Gemma the
bullet names — the sanitizer, the recall index's `text-embedding-005`, and `gemini-2.5-pro`
alongside the mandated `gemini-3.5-flash`. The +0.2-per-model bonus caps at +0.6 either way,
and a judge may reasonably count "Gemini" once; the draft lists all four and lets them.
