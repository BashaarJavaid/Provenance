# ADR-031 — The Sweeper is a clock, not a re-verifier: §6.5's yes-branch has no source, so item 29 ships the no-branch and says so

**Status:** Accepted

**Decision:** `provenance/sweeper.py` walks every belief in the store on a five-minute tick and
calls `policy.expire()` on each one; `expire()` is a **third public door** beside `commit()`
and `retract()`, re-reading the version in force and appending an `UNKNOWN` version when its
`expires_at` has passed. The new version carries the predecessor's `expires_at`,
`half_life_days`, `threshold` and evidence set forward unchanged, and a confidence that is §4.3
**recomputed as of the sweep**. Two `CommitReason` words are added (`EXPIRED`, `NOT_DUE`),
neither in `COUNTED_REJECTIONS`, and one `BeliefOutcome` word (`EXPIRE`) on the existing
`belief.commit` span. The loop is an `asyncio` task started by `app.py`'s lifespan.

**§6.5's yes-branch is not built.** "Re-verification source available?" is always *no* in this
system, and this ADR is where that is recorded rather than papered over.

**Reasoning, in order of weight:**

1. **There is no re-verification source, and inventing one would be tuning the fleet.** §6.5's
   yes-branch re-verifies and commits `CONFIRMED` or routes to §6.4. The only thing in this repo
   that produces those three words is the Verification Agent, and §5.8 makes it deliberately
   narrow: it judges *one predicate declared before an execution* against measurements code took
   after it. A sweep has no execution, no predicate and no post-state — the agent could only be
   handed the belief itself and asked whether it still feels true, which is the assertion §7.2
   exists to keep out of memory ("a memory system that learns confidently from unreliable
   verification is worse than one with no memory at all"). The two ways to manufacture a source
   were both rejected: re-reading the synthetic company deterministically would give exactly one
   entity shape a source and nothing else, and adding a re-verification role would put a model's
   opinion on the yes side of a clock. ADR-029's posture, applied a third time: state the split.
   **What ships is therefore §10's Sweeper row exactly** — "expire a belief with no
   re-verification source; assert it is `UNKNOWN(stale)`, excluded from recall, never deleted."

2. **A third door rather than a flag on `commit()`.** A sweep has no proposal and no proposing
   agent, so §2.2's stages 2 through 5 have nothing to act on: no standing to read, no evidence
   to check for novelty, no threshold to clear. Routing it through `commit()` would mean a
   bypass branch at every one of those stages — a pipeline whose every step is about evidence,
   asked to write a status that rests on none. `expire()` is the same move item 15 made for
   §6.4 and shares stage 6 with both other doors, so the counter, the signature and the one span
   are written in exactly one place. The alternative at the other extreme — the Sweeper calling
   `beliefs.append()` itself — was rejected outright: §5.10 makes the Policy Engine the
   authority over what the organization believes, and a status written around it is §1.1
   property 2 with an exception.

3. **`expire()` re-reads the version in force; the Sweeper does not hand it one.** The walk and
   the write are two moments, and a commit landing between them refreshes `expires_at`.
   Downgrading a belief somebody just re-affirmed is the one wrong answer this door can give, so
   the door checks the clock against a version it read itself, narrowing the race to
   `append()`'s `create()` — which loses rather than clobbers and comes back as
   `VERSION_CONFLICT`. The cost is one extra read per swept belief and a second reason word.
   Taking the version from the caller instead would have saved both and made the Sweeper's walk
   load-bearing for correctness.

4. **The downgrade carries the old clock, and a recomputed number.** `expires_at` is *the reason
   the version exists*, and the belief inspector already renders an overdue expiry in red — so
   carrying it forward makes the visible reason and the stored fact the same thing. A fresh
   `now + half_life` would have said a stale belief is good for another thirty days. The
   confidence is §4.3 as of the sweep for §1.1 property 3: a hardcoded `0.00` is a number no
   formula produced, sitting on a version document, in a system whose whole defence is that its
   numbers are computed. What it records is the decayed truth at the moment the clock fired,
   which is exactly what the inspector's "as of now" line already shows. `threshold` and the
   evidence set are carried unchanged because no gate ran and §6 subtracts nothing.

5. **`UNKNOWN` carries no reason field.** §3.2 writes it `UNKNOWN(reason=stale)`, and
   `recall.DROPPED_STATUSES` compares the exact string, so the status cannot carry it. A field
   was rejected: the Sweeper is the only writer of `UNKNOWN` and §6.5 gives it one reason, so an
   `UNKNOWN` version is stale by construction and the `expires_at` it carries is the evidence.
   A second writer with a second reason is what would make the field necessary; there is none.

6. **`EXPIRE` is a word in the belief-span vocabulary, not a fifth span shape.** §8.1 has held
   at four shapes since item 2, and this write is the same §2.2 stage 6 as the other three — a
   status written, signed and reported. Reusing `COMMIT` was rejected for the opposite reason:
   the gateway ledger and the trace UI would say the organization *committed* a belief at the
   moment it stopped believing it. `EXPIRE` is deliberately not in `telemetry._ERROR_OUTCOMES`;
   a belief reaching its own expiry date is the system working.

7. **Nobody's standing moves.** `EXPIRED` and `NOT_DUE` are the only two reasons in
   `CommitReason` that are not statements about an agent's evidence, so neither is in
   `COUNTED_REJECTIONS` — there is no proposing agent for a refusal to count against. The
   Sweeper holds no registry record for the same reason: it proposes nothing and reasons about
   nothing, so §3.4's authority fields have nothing to read. It is still *named* — the version's
   `authority` reads `staleness-sweeper@v1 (§6.5)` and the span carries the same id — because "a
   clock fired" and "an agent asserted this" must not look alike to anyone reading either. The
   span's required `agent.standing` reports `GOOD`, which is the only value in the enum that is
   not a claim about a refusal; reusing `_standing(None)`'s `SUSPENDED` would have said this
   write was treated as coming from a suspended agent, and it was written. `committed_by` stays
   `memory-policy-engine`, which is true: the clock is only what asked.

8. **A lifespan task rather than a route or a scheduler, and what that costs is stated.** §5.11
   asks for a long-running async process and the track's runtime requirement scores one, so it
   is one. A token-guarded `POST /sweep` would have been a cron with a public surface to guard,
   and Cloud Scheduler adds a paid resource for a loop nothing waits on. What the choice costs
   is real and is not hidden: the service runs at `--min-instances=0`, so **the Sweeper consumes
   expiry while an instance is warm, not on a calendar**. Anything that needs a sweep on demand —
   the verify script, a demo beat — calls `sweeper.sweep()` directly, which is also why no route
   was needed. `SWEEP_INTERVAL_SECONDS = 300`: the walk is roughly a dozen reads, so five
   minutes is ~3k reads/day even with a demo tab pinned open holding the instance warm, leaving
   the registry panel's budget (ADR-030 §7) intact. A minute would be four times that.

9. **The walk is N+1 and the one shortcut is forbidden.** Root documents carry no status,
   confidence or `expires_at` — that is ADR-005's guarantee that the recall index *cannot* see
   currency even by accident — so nothing in the store can be queried for "expired".
   `beliefs.belief_ids()` streams the roots and `current()` resolves each, which at this store's
   size is a dozen reads. Mirroring `expires_at` onto the root to make it one query is the thing
   that must not happen, and it is named here because item 29 is the first item that would want
   it. The honest upgrade path, if the store ever grows, is a collection-group query on
   `versions` filtered by `expires_at` — which needs a composite index and still needs
   `current()` per hit to check the version it found is the one in force.

10. **Skip and retry, rather than abort.** A belief that cannot be read or written is left
    exactly as it was — still past its clock — so the next tick sweeps it again, and nothing is
    half-written. Aborting the whole tick on the first error makes nothing safer and leaves the
    beliefs the sweep could have handled stale as well. `expire()` is the one place that
    *raises* rather than refusing, and only where it could not read the version in force: there
    is no entity, no domain and no status to report a decision about, so there is no decision and
    no span. The loop itself lets nothing escape but cancellation — an exception killing the task
    is a service that silently stops consuming expiry for the rest of its life.

11. **A swept belief is never swept again, and that is not tidiness.** `expire()` refuses
    anything already `UNKNOWN` or `RETRACTED`. Without that refusal a warm Cloud Run instance
    appends a version every five minutes forever — an append-only store's version of a leak,
    and the one failure mode of this design that grows without bound.

**Consequences.** The Policy Engine has three public doors and `CommitReason` has two words that
are not about evidence. `UNKNOWN` is now written, which makes item 16's decision to teach recall
about it before anything wrote it pay off exactly as intended — no read path changed in item 29.
The belief inspector gained one ternary so `UNKNOWN` reads red beside `RETRACTED`. And the
deployed service now does something when nobody asked it to, which is new: every previous write
in this system was downstream of a trigger.

**The live finding, and it is dated.** `belief-SUP-042` expires **2026-09-22** and
`belief-service.tier2` expires **2026-09-24**, both before the **October 1** judging window.
From those dates a warm instance will sweep them, and `SUP-042`'s chain is the closing shot of
the demo and the state items 27 and 28 both proved byte-identical. This is the Sweeper being
correct — the belief genuinely will be a month unverified — so no carve-out was added: a
protected-belief skip list would put demo choreography inside the control plane and leave the
inspector showing an expired belief nothing swept, which is the "valid until is worthless" state
§6.5 exists to end. The fix is the mechanism the design already has: before Sept 22, commit one
fresh corroborating evidence item to `SUP-042` through the normal pipeline, which supersedes v2
and resets the clock. `CLAUDE.md` carries the date as a live trap.

**Revisit when:** a re-verification source actually exists — the most likely one is item 30's
approval queue, where a human confirming a belief is still true is a `verified_system_observation`
a sweep could ask for, at which point §6.5's yes-branch has something real behind it; the store
grows past the point where an N+1 walk is free (reason 9); a second writer of `UNKNOWN` appears
(reason 5); or Cloud Run is ever run at `min-instances > 0`, at which point the loop's calendar
caveat in reason 8 stops applying and the tick interval's read budget is worth re-measuring.

**Alternatives considered:** building §6.5's yes-branch with the Verification Agent, or with a
deterministic re-read of the synthetic company (reason 1); a flag or `UNKNOWN` status path
through `commit()` (reason 2); the Sweeper calling `beliefs.append()` directly (reason 2);
`expire()` taking the version the walk read and returning `BeliefCommit | None` (reason 3);
unconditional expiry with the eligibility rule owned by the Sweeper (reason 3); a fresh
`now + half_life` on the downgrade (reason 4); a hardcoded `0.00` confidence, or carrying the
predecessor's number unchanged (reason 4); an `unknown_reason` field on `BeliefVersion`, or
repurposing `on_expiry` to record what happened (reason 5); reusing `COMMIT` on the wire, or a
fifth `provenance.belief.expire` span shape (reason 6); giving the Sweeper a registry record and
minting it standing (reason 7); reporting `SUSPENDED` via `_standing(None)`, or adding a fourth
`Standing` value (reason 7); a token-guarded `POST /sweep`, both a loop and a route, or a
script-only sweeper with nothing on the deployed service (reason 8); a 60s and a 15s tick
(reason 8); a collection-group query on `versions`, or mirroring `expires_at` onto the root
document (reason 9); aborting the tick on the first error, or reporting an unswept belief through
`/health` (reason 10); a protected-belief skip list, dropping the lifespan loop, or extending
`HALF_LIFE_DAYS["supply-chain"]` past Oct 1 (the live finding above).
