# Devpost submission — draft text

**What this is:** ROADMAP item 35's draft, kept here so the submission form is a paste rather
than a writing session at 4:50 PM on the 31st. Everything below is either written for the form
or copied from a document that owns it — where it is copied, this file says so and links the
owner, because the rule everywhere else in this repo is that one fact has one home. The two
deliberate verbatim copies are the pre-existing-code disclosure table (the rules require it
*verbatim* in the submission text) and the model-compliance sentence.

Nothing here is published. Publishing is items 33–36 and 38.

---

## Category

**Fortified Enterprise Fleet.**

## Elevator pitch

An LLM never decides what the organization does, and never decides what the organization
believes. Provenance is a fleet of agents that detects, diagnoses, fixes and verifies
enterprise incidents — and every state change and every committed belief passes through
deterministic code that no amount of model confidence can move.

## What it does

A monitoring signal wakes the fleet. Six things then happen, and only two of them are decisions.

- **It recalls what the organization already believes** about the affected entity — and about
  the *class* the entity belongs to — before diagnosis begins.
- **A domain agent diagnoses** against that prior belief rather than from a blank page.
- **A planner emits exactly one typed action** — action class, target, blast radius,
  reversibility, evidence references. Never free-form text, and there is no `params` field to
  smuggle anything through.
- **The gateway decides.** Identity, then RBAC/ABAC, then a deterministic risk table, then a
  signature. It is architecturally the only path from any reasoning agent to a state-mutating
  action — the module exposes two public coroutines and a test pins the count at two. Risk is a
  lookup, not a judgement, so an agent cannot argue its way past a threshold.
- **Anything past the threshold parks in front of a human** — a store operations manager, not
  an engineer — as a plain-language card carrying what the fleet wants to do, what it found, and
  the risk arithmetic term by term. The incident survives a process restart while parked and
  resumes on the answer.
- **Verification is three-valued**, judged against a success predicate the planner declared
  *before* execution, and memory learns only from what verification could settle: `CONFIRMED`
  commits what worked, `REFUTED` commits the negative belief, `INCONCLUSIVE` writes nothing at
  all. No partial credit.

The memory write path deliberately mirrors the action path: a Memory Analyst *recommends* and a
deterministic Memory Policy Engine *decides*. Confidence is computed from typed evidence by a
published formula, never asserted by a model. Beliefs are append-only — supersession and
retraction, never overwrite, never delete — and a long-running Staleness Sweeper downgrades
expiring beliefs to `UNKNOWN(stale)` rather than quietly letting them look fresh. Class beliefs
are advisory by two independent mechanisms: they may reorder hypotheses, and they may never
authorize an action or serve as evidence for a commit.

Six operator surfaces ship with it: live fleet view, gateway ledger, belief inspector, registry
panel, approval card, counterfactual panel.

## How we built it

Python 3.12, Google ADK 2.0 (Graph Runtime), FastAPI, Firestore, Vertex AI, Cloud Run,
OpenTelemetry → Cloud Trace. Async throughout. One Cloud Run service at `--max-instances=1`
and `--min-instances=0`. 562 tests in CI with no cloud credentials, plus a live verification
script per roadmap item that reads its result back from the authoritative source and exits
non-zero on a mismatch — claims in this repo are checked by mutating the code and confirming
the suite goes red, and three items recorded a first mutation attempt that was wrong about
itself rather than about the tests.

Full design: `ARCHITECTURE.md`. Every significant decision, including the alternatives that
were rejected, has its own file in `docs/adr/`.

## Google AI models integrated

> The mandatory model requirement is met by `gemini-3.5-flash` via Vertex AI — it is the
> verification judge on every incident. Reasoning roles run GA `gemini-2.5-pro` because the
> 3.x line has no GA Pro, and a preview model can change or be withdrawn inside the October 1
> judging window.

*(That sentence is the one from `README.md`'s tech-stack table and `docs/submission.md` §4;
the catalog probe behind it is `ROADMAP.md` item 1's deviation note.)*

| Model | Role | Where a judge can see it |
|---|---|---|
| `gemini-3.5-flash` | **Verification Agent** — the three-valued verdict that gates whether memory learns anything | Every incident's trace; the `verification` field on the trigger response |
| `gemini-2.5-pro` | Four reasoning roles — Orchestrator, domain agents, Remediation Planner, Memory Analyst | Every incident's trace, one span per role |
| `gemma-4-26b-a4b-it-maas` | **Sanitizer** — reduces untrusted external content to typed facts and tokenizes residual PII, in isolation, before any of it reaches a frontier model | The injection arc's trace |
| `text-embedding-005` | **Recall index** — nominates candidate beliefs; the store decides what is true | The recall span on any incident with prior memory |

Four models, each load-bearing. There is no Veo, Lyria or Imagen integration: one honest model
beats three ornamental ones, and the sanitizer and the embedding index are both places where
removing the model breaks a security or memory guarantee rather than a decoration.

## Data sources

- **`google/adk-samples` Customer Service dataset (Apache-2.0)** — base entity model only.
- **Everything else is authored**: all services, suppliers, config versions, tier assignments,
  fault-injection switches, the belief fixtures, and the registry.

**On the synthetic fixture, stated plainly rather than hidden.** This track is about compliance
and governance, and the honest constraint is that you cannot demonstrate governance on real
production incident data — the data is exactly what governance exists to protect. A small,
internally consistent synthetic company is what *permits* the attack arcs to be run for real:
a live prompt injection and a live memory-poisoning attempt, both executed against the deployed
service rather than described, because there is nothing real to damage. The fixture is the
reason the security beats are live instead of hypothetical.

## Findings and learnings

**The headline finding is negative, and it is the one we lead with.** The sixth operator surface
is an A/B measurement of what memory is actually worth: the same incident run with recall on and
with `--memory-disabled`, twelve live incidents, six of them measured. The result is titled
*"Memory made incident #2 cost 34% more wall-clock and changed nothing it concluded"* — the two
arms are identical in model calls, hypotheses, diagnosis, verdict and committed confidence, and
differ only in what they spent. The cause is a ceiling, not a defect: the domain agent's prompt
has carried a config-regression hint since the first incident item, so it reaches the right
diagnosis with or without a recalled belief and a metric measuring the diagnosis has no room to
move. We published the negative result, kept the hint, and did not go looking for a metric that
flattered the design. Method and full numbers: `docs/counterfactual-report.md`.

The claim the project actually makes about memory is not that it is faster. It is that belief
becomes governed and inspectable — versioned, provenanced, computed, expirable, retractable, and
impossible for an agent to write on its own authority.

**Two defects were found by running the system, not by reading it.**

- **A hold reason attributed to the wrong agent.** The approval card derives why an action was
  held, and the first version read `routed_to`. But standing belongs to the *proposer*, and the
  two are routinely different — a domain agent reasons about the incident while the planner
  proposes the action. Every fixture using one agent for both roles passed either way; only the
  live queue exposed it. (`ADR-033`)
- **A bare assertion could overturn a belief.** A source class weighing 0.00 corroborates
  nothing, but confidence flips are scored over the *accumulated* evidence set, so an item
  contributing zero still rode along on a set already past the flip threshold — and an
  unverified external claim overturned a belief it should not have been able to touch. The fix
  was to filter the flip test's novel side by base weight. The item existed to demonstrate a
  defence, and it found the defence incomplete.

**A design decision that did not survive contact.** The parked-approval path was specified
against an ADK Task API. There is no ADK Task API — there are primitives to assemble, and the
two available session backends both fail here (one writes to a filesystem Cloud Run discards on
scale-to-zero, which a five-minute park at `min-instances=0` is guaranteed to meet; the other
requires an Agent Engine that bills while idle). The ADR is marked superseded in part rather
than rewritten, because the record of a choice that did not survive is the useful part.

**What we would tell someone starting this.** Write the verification criterion before the
feature. Every roadmap item here carries a `verify:` line, and the ones that produced findings
are the ones whose verify line was discharged by running against the real thing — real Firestore,
real Gemini, live registry state — rather than against a fixture that agreed with us.

## Pre-existing code disclosure

*(Reproduced verbatim from `README.md` as the rules require. `README.md` is its home; if the two
ever disagree, the README is right.)*

Contest rules require projects be newly created during the submission period and that pre-existing code be disclosed. PortunusMCP touches two of the track's named pillars (Agent Identity, Agent Gateway), so the exposure is handled structurally, not just rhetorically: **PortunusMCP enters this repo as a library dependency** — the way any project consumes an off-the-shelf auth framework — and every line of track-facing logic is new code in this repository, visible as such in the commit history.

The separation is independently verifiable: **PortunusMCP `0.1.0` was published to PyPI on 2026-07-27**, a week before the submission period opened on August 3 — a third-party timestamp, not a claim. It is installed by exact version pin from PyPI ([`portunusmcp`](https://pypi.org/project/portunusmcp/), MIT); nothing is vendored, forked, or copied into this tree.

| Component | Status | What is new here |
|---|---|---|
| PortunusMCP — **three modules only**: `signing` (ECDSA), `abac` (condition grammar), `decision` (typed models). 295 of its 7,347 lines | **Pre-existing**, authored by me, published to PyPI 2026-07-27 and consumed by version pin | Everything the track actually scores: the deterministic risk table, reversibility/blast-radius fields on typed actions, registry standing and its request-time reads, agent identity resolution and short-lived credential minting, the human-approval hold/resume path, the approval card. Portunus supplies crypto and condition-parsing plumbing — the moral equivalent of an auth library. Its own identity broker, risk engine, and policy engine are **not** used |
| ProdRescue (LangGraph triage → fix → validate → retry SRE loop) | **Pre-existing**, authored by me | Loop *shape* informed the SRE agent; the ADK/Gemini implementation, the gateway-gated execution path, and three-valued verification are new |
| `google/adk-samples` Customer Service dataset | Third-party, Apache-2.0 | Base entity model only; all services, suppliers, config versions, and fault injection are authored |
| Determinism boundary, typed evidence, computed confidence, class beliefs, retraction, decay, standing | **New** | The substance of the submission |

The ratio is the point: the four pillars judges score — registry, runtime, memory, governance — are new work built during the submission period; what is reused is undifferentiated infrastructure beneath them.

## Try it

- **Hosted:** https://provenance-808273007560.us-central1.run.app
- **Repository:** https://github.com/BashaarJavaid/Provenance

The README's **Run the demo** section walks a cold visitor through the whole thing with nothing
but the URL — the trigger token is published there, the supply-chain incident is repeatable and
mutates nothing, and the approval flow can be completed in the browser. Reproducible spin-up
from a clean checkout is the README's **Quickstart**: one install command (two steps, and the
README explains why), one setup script, one deploy script that checks its own result.

## Built with

`python` · `google-adk` · `gemini` · `gemma` · `vertex-ai` · `cloud-run` · `firestore` ·
`fastapi` · `opentelemetry` · `model-armor` · `portunusmcp`

---

## Checklist before pasting this in

- [ ] Video URL exists and is public (YouTube or Vimeo), under 4:00 evaluated
- [ ] Blog post published with the required "created for the purposes of entering this
      hackathon" line — item 33
- [ ] Social post published with **#AllThingsAgenticHackathon**, linking video and repo — item 34
- [ ] Hosted URL responds and the approval flow works cold — item 36
- [ ] Repository public, architecture diagram present (`docs/architecture.svg`, embedded in the
      README)
- [ ] Both `docs/blog-draft.md` and `docs/social-draft.md` links updated to the published URLs
