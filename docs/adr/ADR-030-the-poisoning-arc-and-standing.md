# ADR-030 — A source class that weighs nothing cannot corroborate a flip, and the standing arc runs on two agents because no one agent can carry it

**Status:** Accepted

**Decision:** §6.3's class test filters its **novel** side by weight: a flip commits only if its
new evidence contributes a `source_class` with `BASE_WEIGHT` above 0.00 that the version in
force does not already rest on. `known` is not filtered. This is the only production change to
the decision path in item 28; `CommitReason`, `COUNTED_REJECTIONS`, `registry.py` and every span
shape are untouched, and the poisoning is refused under the existing `FLIP_UNSUPPORTED`.

Item 28's live half is one script, `scripts/verify_poisoning_arc.py`, which drives the arc with
**scripted proposals and no model calls**, against the real seeded `SUP-042`. It exercises the
memory half on `supply-chain-agent` and the gateway half on `remediation-planner`, set
`DEGRADED` by hand, and it says in its own docstring that these are two agents and why. §8.2's
registry panel is filled by a new unauthenticated `GET /registry`.

**Reasoning, in order of weight:**

1. **The item's premise was false as implemented, and that is the finding.** §10's poisoning row
   and `THREAT_MODEL.md` both describe the defence as *confidence unmoved*. That is true of the
   number and false of the outcome. A flip is measured over the **accumulated** set (ADR-017),
   so `unverified_external_claim` at 0.00 leaves confidence at whatever the belief already had —
   and `SUP-042` sits at **0.7477**, past `FLIP_THRESHOLD`. The threshold gate therefore passes
   *on the strength of the very evidence the poisoner is contradicting*, and the class test
   passed too, because a plain set difference counts a class that contributes nothing. The
   poisoning committed. Reproduced before the fix and again after it: with the filter reverted,
   attempt 1 lands `COMMIT/ABOVE_THRESHOLD` at 0.7698 and `SUP-042` reads `CLEARED`.

2. **The filter goes on the novel side because that is the side the rule is about.** §6.3 asks
   what the *claim* brings. Filtering `known` as well changes no reachable outcome — a
   zero-weight class already in force fails the plain difference anyway — so it would be an
   inert line that a reader has to work out is inert. Two mutation checks pin this: dropping the
   filter and moving it to `known` both turn item 28's tests red.

3. **`FLIP_UNSUPPORTED` rather than a new reason, and rather than `BELOW_THRESHOLD`.** The
   refusal that is *true* here is the class one: the number was fine and the corroboration was
   not. `FLIP_UNSUPPORTED` already means exactly that (ADR-018 reason 3), and it is already in
   `COUNTED_REJECTIONS`, so the standing counter fires with nothing in `registry.py` changing.
   Routing the poisoner to `BELOW_THRESHOLD` instead — by refusing an all-zero-weight flip
   before stage 5 — would have matched item 14's live script but would put a reason on the span
   that misdescribes what happened, and add a fourth door to a pipeline that has three.

4. **Two agents, because one cannot do it and manufacturing one would be tuning the fleet.**
   §10's standing row wants a DEGRADED agent's *ordinary low-risk proposal* held. The gateway
   checks `tool_scope` (stage 4a) **before** it evaluates standing (4b), and no registered agent
   both holds a memory domain and holds a tool scope: `supply-chain-agent` would be denied
   `TOOL_SCOPE` and never reach `STANDING_DEGRADED`. The two ways to make one agent carry both
   were rejected — giving a belief-proposing domain agent an action scope inverts §5's split and
   would need a hand-write to a seeded record (`--rotate` copies the *stored* record, so editing
   `registry.AGENTS` does not propagate), and giving the Planner a memory domain makes it a
   belief author. So the script degrades `remediation-planner` with `registry.set_standing()`,
   which §3.4 already calls a human act, and both halves are live and separately true. This is
   ADR-029's posture: state the split rather than script around it.

5. **Scripted proposals, no model calls.** Every claim item 28 makes is about the Policy Engine,
   the registry and the gateway; none of them is about what a model said. Driving the arc
   through `run_incident()` would add three `gemini-2.5-pro` calls per run and couple a
   determinism claim to a sampled output — item 8's and item 14's posture, for the same reason.

6. **The panel reads Firestore, not the span stream.** ADR-021's exception applies again and
   more sharply: standing is *stored* state, and the trace buffer is in-process and bounded, so
   a counter derived from spans can disagree with the registry it claims to show — and the
   moment the panel exists for is the moment the two would diverge. `GET /registry` reads
   through `registry.get_agent()` per request (§1.1 property 4) and fails **closed**: a
   `RegistryError` is a 503, because an empty or all-GOOD panel during an outage is the one
   wrong answer this surface is able to give.

7. **5s, not 1s and not 15s.** The transition has to land inside one narration beat, which 15s
   does not guarantee, and the 1s trace cadence would be four document reads a second — roughly
   350k/day from a tab left open, against a 50k/day free tier. 5s is ~69k/day. The $300 ceiling
   is a design constraint here, not something audited afterwards.

8. **The script restores, and refuses to start dirty.** `verify_belief_store.py`'s posture
   exactly: it refuses unless both agents begin GOOD with an empty window, and the `finally`
   restores on every exit path. Restoring the window is a **direct document write** —
   `registry.py` has one standing writer and no un-append path, and must not grow one. Leaving
   the agent DEGRADED would be the more literal reading of "the system never quietly forgives",
   but it makes the script single-use, and item 37 rehearses it repeatedly.

**What this costs:** a flip can no longer be corroborated by a class carrying no weight, which
in principle narrows the legitimate-update case too — in practice it cannot, because the only
zero-weight class in §4.3 is `unverified_external_claim` and a belief resting on it alone was
never reachable. `BASE_WEIGHT` is now load-bearing in a *second* place: adding a class at 0.00
would silently make it unable to corroborate anything, which is correct but is now a second
consequence of one number. The panel adds a second Firestore-reading route to a public service —
what it publishes is standing and the reasons that earned it, recorded in `THREAT_MODEL.md`. And
the two-agent split means §10's standing row is proven by two facts rather than one narrative;
the demo script says so out loud rather than eliding it.

**Revisit when:** a human reinstatement path lands in the product (ADR-018's clause, now also
ADR-030's — the script's direct window write becomes a product decision); item 29's Sweeper
writes `UNKNOWN(stale)`, at which point the panel may want to show what a stale belief did to an
agent's authority; item 30's approval queue gives the held `ROLLBACK_CONFIG` somewhere to park,
making the gateway half of this arc a resumable incident rather than a scripted `authorize()`;
or a source class with weight 0.00 is added for some reason other than being unverifiable, at
which point reason 2's filter is answering a question nobody asked it.

**Alternatives considered:** leaving §6.3 alone and pointing the arc at a fresh entity with no
belief, where 0.00 is refused `BELOW_THRESHOLD` (reason 1 — it proves item 14's claim again,
leaves "SUP-042 still AT_RISK" trivially true, and leaves the hole in the repo); re-seeding
`SUP-042` older so decay drops it under 0.50 (forbidden — `seed_belief.py` has no `--reset` for
exactly this reason, and it would make the defence a function of the calendar); measuring a flip
over the **novel** items alone, mirroring §6.4's retraction door (reason 1 — it would stop the
poisoner, and it would also un-commit item 17's v2, which is a lone `third_party_audit` at
0.55); refusing an all-zero-weight flip before stage 5 under `BELOW_THRESHOLD` (reason 3);
filtering both sides of the set difference (reason 2); giving `supply-chain-agent` a tool scope,
or `remediation-planner` a memory domain (reason 4); driving the arc through `run_incident()`
(reason 5); deriving the panel from `GET /trace` so ADR-015's one-stream claim keeps no second
exception (reason 6); `GET /registry/{agent_id}` mirroring `/belief/{entity}` (the DEGRADED row
then has no GOOD peers to read against, which is what makes it legible); serving `public_key` on
the route because the record carries it (a field served because it was there is a field the next
reader assumes something depends on); returning the records that answered and omitting the rest
(reason 6 — a missing row reads as absence, not as uncertainty); and a `--leave-degraded` flag
for the recorded take (reason 8 — a flag used once, on camera).
