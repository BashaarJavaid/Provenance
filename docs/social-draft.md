# Social post — draft

**What this is:** ROADMAP item 34's draft. **Publish last** — every version below needs the
video URL, so this goes out after item 38. One public post on X or LinkedIn, carrying the
hashtag **#AllThingsAgenticHackathon** exactly as written (it is what the bonus is scored on),
linking both the video and the repo. Put the published URL on item 34 and in
`docs/devpost-draft.md`.

Replace `<VIDEO_URL>` before posting. Repo: https://github.com/BashaarJavaid/Provenance

---

## Option A — X, single post

> Most agent architectures draw a "policy engine" box in a different colour, then feed it
> `if plan.confidence > 0.8`. The authority never moved — it changed costume.
>
> Provenance draws the line where it holds: an LLM never decides what the org does, and never
> decides what the org believes. Risk is a lookup table. Confidence is arithmetic over typed
> evidence. Neither takes a number a model produced.
>
> Built on Google ADK, Gemini 3.5 Flash + 2.5 Pro, Gemma 4, Vertex AI and Cloud Run.
>
> I also A/B'd whether memory was worth it and published the result even though it came back
> negative.
>
> 🎥 <VIDEO_URL>
> 💻 https://github.com/BashaarJavaid/Provenance
>
> #AllThingsAgenticHackathon

## Option B — X, thread (use if A runs long)

**1/**
> Most agent architectures cheat at the last inch: a "policy engine" box drawn in a different
> colour, whose decisive input is a number the model produced. `if plan.confidence > 0.8` is not
> a deterministic decision. It's an LLM decision wearing an if-statement.
>
> #AllThingsAgenticHackathon

**2/**
> So I built one where the boundary actually holds. The rule: deterministic code may consume
> typed data, cryptographic identity, registry state, and numbers from published formulas. Never
> a number an LLM produced. The model's job ends at extraction and recommendation.

**3/**
> Consequence: risk is a lookup table. base + tier + blast radius + irreversibility, with a
> threshold that holds for a human. Crude on purpose — a store ops manager can read four numbers
> and a threshold and know why she's being asked. You can't do that with a learned scorer.

**4/**
> Same rule for memory. An analyst model extracts typed evidence but doesn't get to say how
> confident the belief is — that's noisy-OR over source classes, decayed by age. Unverified
> external claims weigh 0.00, so "assert it confidently enough" isn't an attack vector.
>
> (It half-failed on the first try. That story's in the post.)

**5/**
> I built the A/B into the product: same incident, memory on vs off, twelve live runs.
>
> Memory cost 34% more wall-clock and changed nothing it concluded.
>
> I published that as the headline instead of deleting the prompt hint that caused the ceiling.

**6/**
> Google ADK 2.0, Gemini 3.5 Flash (verification) + 2.5 Pro (reasoning), Gemma 4 (sanitizer),
> text-embedding-005 (recall), Firestore, Cloud Run, OpenTelemetry.
>
> 🎥 <VIDEO_URL>
> 💻 https://github.com/BashaarJavaid/Provenance
>
> #AllThingsAgenticHackathon

## Option C — LinkedIn

> **An agent that can act without permission is a liability. An agent that can *believe* without
> permission is a liability that compounds.**
>
> It's become fairly common to gate agent *actions* behind an approval step. It's still rare to
> gate what an agent is allowed to *conclude*.
>
> I spent this hackathon building Provenance around a single rule: an LLM never decides what the
> organization does, and never decides what the organization believes. In practice that means
> deterministic code may consume typed data, cryptographic identity, registry state, and numbers
> computed by published formulas — but never a number a language model produced.
>
> That rule is more restrictive than it sounds. It rules out `confidence > 0.8`. It rules out
> asking a model to rate an action's risk. What it buys is a governance story you can put in
> front of a non-engineer: risk is a four-term lookup table with a threshold, and the human who
> approves a held action is shown the arithmetic rather than a model's opinion.
>
> The same boundary runs through memory. Beliefs are versioned, provenanced, append-only, and
> their confidence is computed from typed evidence rather than asserted. A background sweeper
> downgrades what's gone stale to UNKNOWN instead of letting old confidence keep looking fresh.
>
> I also built the counterfactual in as a product surface — the same incident run with memory on
> and off — and it came back against my own design: recall cost 34% more wall-clock and changed
> nothing it concluded. I shipped the panel that says so. The claim I make about memory was never
> that it's faster; it's that belief becomes governed and inspectable.
>
> Built on Google ADK 2.0, Gemini 3.5 Flash and 2.5 Pro, Gemma 4, Vertex AI, Firestore, Cloud Run
> and OpenTelemetry.
>
> Demo: <VIDEO_URL>
> Code, architecture docs and the ADRs — including the decisions that didn't survive contact:
> https://github.com/BashaarJavaid/Provenance
>
> #AllThingsAgenticHackathon

---

## Before posting

- [ ] `<VIDEO_URL>` replaced everywhere in the chosen option
- [ ] Hashtag reads exactly **#AllThingsAgenticHackathon**
- [ ] Both the video and the repo are linked in the same post (thread: the last one)
- [ ] Post is public, not connections-only
- [ ] Repo is public and the hosted URL in its README responds
