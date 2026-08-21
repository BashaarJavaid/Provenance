# ADR-010 — The agent registry record: flat documents, stored standing, and a window with a number

**Status:** Accepted (revisit if an agent ever needs more than one live version at a time)

**Decision:** The agent registry (`ARCHITECTURE.md` §3.4) is one flat Firestore document per
agent at `agents/{id}`, with `version` as a field. The stored `standing` is authoritative on
every read; it is never recomputed from `rejection_window`. The rolling window §3.4 leaves
unsized is **3 rejections inside 24 hours**, named in code as `REJECTION_THRESHOLD` and
`REJECTION_WINDOW_HOURS`. Every failure raises — no registry function returns `Agent | None`.

**Reasoning, in order of weight:**

1. **Raising rather than returning `None` is what makes fail-closed structural (primary
   reason).** §7.3 requires that an unreachable registry deny, because "an authorization
   without a live standing read violates load-bearing property 4". A `-> Agent | None`
   signature satisfies that only as long as every caller remembers to branch, and the
   failure mode of forgetting is an authorization granted with no standing read at all —
   silently, and in the direction of permitting. `RegistryUnavailable` (Firestore failed),
   `AgentNotRegistered` (no such document) and a bare `RegistryError` (a malformed record)
   all share one base class item 7 catches once and maps to `DENY(stage="registry")`. A
   test walks the module and rejects any function annotated to return an optional `Agent`,
   so the posture cannot be relaxed by accident later.
2. **Stored standing is the only shape that can express human reinstatement.** §3.4 stores
   both a `standing` field and a `rejection_window`, so they can disagree, and something
   has to win. Deriving standing from the window is the tempting choice — it cannot drift —
   but `SUSPENDED` is not derivable from rejections at any count, and "restoration requires
   explicit human reinstatement" needs a field a human can actually set. Derivation would
   also quietly re-degrade an agent a human had just reinstated, which is the opposite of
   §3.4's rule. So the field wins, item 14's Memory Policy Engine writes DEGRADED after the
   third rejection, and `registry.set_standing()` is the single writer either uses.
   `degraded_by_window()` lives here with the two constants but is deliberately not called
   by `get_agent()`: it is the arithmetic item 14 applies *before* it writes, tested now so
   item 14 inherits a checked rule rather than re-deriving one.
3. **The window needed a number and did not have one.** ARCHITECTURE §3.4 and §10,
   `THREAT_MODEL.md`, the spec's §9 and ROADMAP item 28 all say "the rolling window" and
   none of them says how long it is. 24 hours is invented here: long enough that the item-28
   beat (three poisoning attempts seconds apart) lands well inside it, short enough that the
   window genuinely rolls rather than meaning "forever". A `RejectionEntry` carries
   `rejected_at` and `reason` — §2.2's "standing counter incremented" phrasing is satisfied
   by the list's length, and the `reason` is what item 28's registry panel renders when it
   shows *why* an agent degraded. §3.4 now names both constants so there is one number to
   point at instead of a phrase.
4. **A flat document is one read, and the registry is read on every authorization.**
   §1.1's fourth property makes this the hottest read in the system: both the gateway
   (§2.1 stage 3) and the Memory Policy Engine (§2.2) hit it per request. `agents/{id}`
   with `version` as a field answers in one round trip, and matches how `services/{id}`
   already carries `deployed_version` (ADR-009). The alternative shapes both cost something
   real: a `versions/{version}` subcollection is a second read per authorization unless the
   current version is denormalized onto the parent anyway, and `agents/{id}@{version}` as a
   document id puts standing *inside* a version, so degrading an agent would stop following
   it across a version bump — precisely the escape hatch §3.4 exists to close.
5. **The seeder skips existing records whole, which is why "never quietly forgives" is
   true.** `scripts/seed_registry.py` is create-if-absent and has deliberately **no
   `--reset`**, unlike `scripts/seed_firestore.py`. The company fixture wants a between-take
   reset; the registry must not have one, because rewriting the fixture's `standing: GOOD`
   over a stored `DEGRADED` is exactly the quiet forgiveness §3.4 forbids, wearing the
   costume of a routine re-seed. Skipping whole also means each keypair is generated once,
   on first seed, so a re-run cannot invalidate a credential item 7 minted; `--rotate
   <agent-id>` is the one deliberate path to a new key and bumps the version with it. The
   private half is printed once and never written to disk — item 7 decides how a signing
   agent receives it rather than this item inventing a key store it would have to defend.

**What this deliberately does not do:** mint or verify credentials (item 7 — the record
only *stores* `public_key`), append to `rejection_window` (item 14 owns the memory write
path), emit spans (a registry read is a data access, not a decision; item 7 emits
`authorization.decision` carrying the standing it read), or expose an HTTP route (§8.2's
registry panel is item 11's, and `provenance/app.py` still has no route that reads
Firestore). `tool_scope` holds only the two action classes §4.2 actually names, because the
tool registry is item 6 and any further string would be a guess item 6 must honour or delete.

**Revisit when:** an agent needs two versions live at once — a canary alongside a stable
build — at which point the current version stops being a field and starts being a pointer,
and the `versions/` subcollection rejected above starts paying for itself.

**Alternatives considered:** `agents/{id}/versions/{version}` and `agents/{id}@{version}`
(rejected in reason 4); standing derived from the window, or the stored field used as a
floor under a derived value (rejected in reason 2 — the floor variant still puts policy
logic inside a read the gateway must be able to trust as a plain lookup); a scalar
`rejection_count` instead of a list (rejected — §3.4 specifies a list, and a count cannot
roll or explain itself); `Agent | None` returns (rejected in reason 1); a `--reset` flag on
the seeder (rejected in reason 5); writing private keys to a gitignored `.keys/` directory
or to Secret Manager (rejected — the first puts key material in the working tree, the
second adds an API, an IAM grant and a dependency for a demo whose signing story is item 7's).
