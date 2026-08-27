# Blog post — draft

**What this is:** ROADMAP item 33's draft. Source material is `ARCHITECTURE.md` §4, the
determinism boundary; the measurement at the end is `docs/counterfactual-report.md`. Publish on
dev.to or Medium, publicly, before the deadline, then put the URL on item 33 and in
`docs/devpost-draft.md`.

**Two things to check before publishing.** (1) The disclosure line at the bottom is required by
the rules and must not be edited out. (2) This post restates numbers that live in
`ARCHITECTURE.md` §4.2 and `docs/counterfactual-report.md` — a blog post has to be
self-contained, so the copies are deliberate, but re-read both against this draft before
publishing so an external artifact never disagrees with the repo it describes.

Suggested title: **Your agent architecture probably cheats at the last inch**
Suggested tags: `ai`, `architecture`, `googlecloud`, `agents`

---

## Your agent architecture probably cheats at the last inch

Every agent architecture diagram I have seen in the last year has a box in it labelled
something like "policy engine" or "guardrail" or "approval layer." The box is drawn in a
different colour from the agents. The implication is clear: the reasoning happens over here,
and the *deciding* happens over there, in code, where it is safe.

Then you read the code, and the policy engine's decisive input is a number the model produced.

```python
if plan.confidence > 0.8 and plan.risk_assessment == "low":
    execute(plan)
```

That is not a deterministic decision. That is an LLM decision with an `if` statement in front
of it. The authority never moved. It just changed costume.

I spent a build proving to myself that you can draw the boundary somewhere it actually holds,
and that doing so costs less than it sounds like. Here is the rule I ended up with, what it
forced me to give up, and the measurement at the end that came back against my own design.

### The rule

> A deterministic decision may consume: typed data, cryptographic identity, registry state, and
> numbers computed by published formulas. It may **not** consume a number an LLM produced. An
> LLM's role ends at *extraction* and *recommendation*.

Read that second sentence again, because it is the whole thing and it is more restrictive than
it first appears. It rules out `confidence > 0.8`. It rules out asking a model to rate an
action's risk on a scale of one to ten. It rules out a "severity" field on a typed object if a
model filled it in. It rules out the very natural move of having the smart thing tell the dumb
thing how worried to be.

What it leaves you is: the model may say *what is happening* and *what it proposes to do about
it*, in a typed shape you defined. Everything after that is yours.

### Consequence one: risk becomes a lookup table

If a model cannot tell me how risky an action is, something else has to. So risk is a pure
function of the typed action, computed by lookup:

```
risk = base[action_class]
     + criticality_points[target_tier]        # tier1 +2, tier2 +1, tier3 0
     + blast_points[blast_radius]             # org-wide +2, multi-service +1, single +0
     + irreversibility_points[reversible]     # effects-irreversible +3, reversible +0

0–3  → auto-approve
4–6  → auto-approve with notification
7+   → hold for human approval
```

Two worked examples, so that outcomes in a demo are principled rather than convenient:

| Action | base | crit | blast | irrev | total | outcome |
|---|---|---|---|---|---|---|
| `ROLLBACK_CONFIG(inventory-api, v42→v41)` | 1 | +1 | +0 | +0 | **2** | auto-approve |
| `DISABLE_COMPLIANCE_CHECKS(SUP-042)` | 4 | +2 | +2 | +3 | **11** | human approval |

People's first reaction to this table is that it is crude. It is crude. That is the feature.
Three properties fall out of crudeness that I could not get any other way:

**It is auditable by a non-engineer.** The human who receives the hold is a store operations
manager, not an SRE. She can be shown four numbers and a threshold and understand exactly why
she is being asked. You cannot do that with a learned scorer, and "the model felt this was
risky" is not a governance artifact.

**It cannot be argued with.** An agent that is confidently wrong — or one that has been
successfully prompt-injected — still cannot move the number. It does not have access to the
number. The score is computed from the typed action's own fields, and the scoring function
takes the action and nothing else: no confidence, no model output, no free parameter. That is
the rule made structural instead of documentary.

**The worst thing it can say is "ask a human."** The scoring band returns approve, approve-with-
notification, or hold. It never returns *deny*. Every denial in the system comes from who is
asking — identity, registry standing, declared tool scope — not from how bad the action looked.
Risk and authorization are different questions and I stopped letting one answer the other.

I also refused to make the table pluggable, which was the single most tempting piece of
over-engineering in the project. A pluggable risk framework is a place for someone to later
install a model.

### Consequence two: confidence becomes arithmetic

The same rule applies to what the system is allowed to *believe*, and this is where it gets
interesting, because most agent memory systems are a vector store with no opinion about truth.

When an action is verified, an analyst model extracts typed evidence — but it does not get to
say how confident the resulting belief is. Confidence is noisy-OR over distinct source classes,
each weighted by how much that class of evidence is worth and decayed by its age:

```
w_i  = base_weight[source_class] × 2^(-age / half_life)
conf = 1 − Π(1 − w_i)       over the distinct source classes present
```

A verified system observation is worth a lot. An unverified external claim is worth **zero** —
literally 0.00, meaning it corroborates nothing. That last one is not decoration. Someone
attacking this system's memory does not attack the belief store; they attack the *evidence*,
by asserting something confidently and repeatedly until the number moves. If unverified
assertions weigh zero, that attack has nothing to push with.

It half-worked on the first try, and finding out how it half-failed was the most useful hour of
the build. A confidence *flip* — overturning an existing belief — is scored over the accumulated
evidence set. An item weighing 0.00 leaves the accumulated number untouched, which sounds safe,
but it meant a bare assertion could ride along on a set that was already past the flip
threshold and overturn a belief it should never have been able to touch. Zero weight is not the
same as no effect, if the thing you are gating on is a set membership rather than a sum. The fix
was to filter the flip test by base weight. The lesson was that "this contributes nothing" and
"this changes nothing" are different claims, and I had checked the wrong one.

### Consequence three: the model gets a smaller job, and does it better

The thing nobody warns you about is that this is *nicer to build against*. The planner emits one
typed object with eight fields and no free-form escape hatch — no `params` dict, no
`raw_content` — because every field a model can fill with prose is a field somebody will
eventually read as an instruction. Once the object is that narrow, "did the model do its job"
becomes a schema check instead of a judgement call. Failures become loud and early instead of
quiet and late.

And the boundary makes the failure modes composable. Verification is three-valued —
`CONFIRMED`, `REFUTED`, `INCONCLUSIVE` — and memory learns only from the two that settle
something. `CONFIRMED` commits what worked. `REFUTED` commits the *negative* belief, because a
confirmed refutation is knowledge. `INCONCLUSIVE` writes nothing at all, with no partial credit,
because a system that learns from its own confusion accumulates confident nonsense. In the code
that rule is the shape of a two-entry dictionary rather than a branch: `INCONCLUSIVE` has no
entry, so committing on it would mean adding a key, which is a much harder thing to do by
accident than deleting an `if`.

### Then I measured whether any of it was worth it, and it wasn't — on the axis I measured

Here is the part I would rather not write.

The obvious claim for a system like this is that institutional memory makes it *faster*: recall
the prior belief, skip the dead-end hypotheses, resolve sooner. I built an A/B into the product
as a first-class surface — the same incident, run with recall on and with recall disabled —
because I did not want to assert that claim without a number behind it.

Twelve live incidents against real infrastructure and a real model. Six measured. The result:

**Memory made the incident cost 34% more wall-clock and changed nothing it concluded.** Same
model calls, same hypotheses considered, same diagnosis, same verdict, same committed
confidence. The two arms were identical in every respect except what they spent. The ranges did
not even overlap — 49.7/52.3/55.7 seconds with memory, 38.7/39.0/41.8 without.

The cause turned out to be a ceiling, not a defect. The domain agent's prompt already contains a
hint that makes this particular diagnosis reachable — if the deployed config version is ahead of
the last known-good one and the deviation began after it, suspect a config regression. On this
fixture that precondition is true, so the agent gets there with or without a recalled belief,
and a metric measuring the diagnosis has no room to move.

I could have deleted the hint. It would have produced a flattering chart in about twenty
minutes. I left it in, published the negative result as the headline, and shipped the panel that
displays it, because the alternative is a benchmark designed backwards from its conclusion —
and because the claim I actually make about memory was never about speed. It is that belief
becomes *governed*: versioned, provenanced, computed rather than asserted, expirable,
retractable, and impossible for an agent to write on its own authority. None of those are things
a stopwatch can see.

The full unedited run is in the repo, gRPC noise and all:
[`docs/counterfactual/session.log`](https://github.com/BashaarJavaid/Provenance/blob/main/docs/counterfactual/session.log),
alongside the six per-run JSON artifacts the table is derived from. The report re-derives itself
from those artifacts in CI, so the prose cannot drift from its own evidence without the build
going red.

### The line I keep coming back to

An LLM never decides what the organization does, and never decides what the organization
believes.

Both halves matter, and the second one is the half people skip. It is now fairly common to gate
*actions* behind human approval or a policy check. It is still rare to gate what the system is
allowed to *conclude* — to say that the memory write path mirrors the action path exactly, that
the analyst recommends and a deterministic policy engine decides, that beliefs are append-only
with supersession and retraction rather than overwrite, and that a background sweeper downgrades
what has gone stale to `UNKNOWN` rather than letting old confidence quietly keep looking fresh.

An agent that can act without permission is a liability. An agent that can *believe* without
permission is a liability that compounds, quietly, until someone asks it why.

---

Code, architecture docs, ADRs including the decisions that did not survive contact, and a live
deployment: **https://github.com/BashaarJavaid/Provenance**

*This project and post were created for the purposes of entering this hackathon.*
