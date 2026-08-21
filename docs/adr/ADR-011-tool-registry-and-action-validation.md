# ADR-011 — The tool registry is a constant, the Action has eight fields, and validation raises

**Status:** Accepted (revisit when a tool's schema must change without a deploy)

**Decision:** The tool registry (`ARCHITECTURE.md` §3.1) is an in-code frozen constant,
`provenance/tools.py`, not a Firestore collection — the one registry in this system that is
*not* read at request time. A `Tool` carries four fields: `action_class`, `target_kind`, and the
authoritative `reversible` and `blast_radius`. It does not carry `base[action_class]`. The typed
Action keeps exactly §3.1's eight fields and gains no `params`. `validate()` accepts `object`,
raises an `ActionError` hierarchy, emits no span, and is synchronous. The once-then-escalate
rule ships as a stateless `outcome_for(attempts)`.

**Reasoning, in order of weight:**

1. **A tool's reversibility cannot change, and the thing that can must not look like it
   (primary reason).** §1.1's fourth property — "the registry is read at request time, not at
   boot" — exists because standing changes mid-run and an authorization against a stale read is
   an authorization with no standing read at all. Nothing analogous is true of a tool:
   `DISABLE_COMPLIANCE_CHECKS` is irreversible as a fact about the world, and `THREAT_MODEL.md`
   already assumes "registry entries are hand-authored and reviewed". Storing it in Firestore
   would buy a mutability nobody wants and cost a network read on the hottest path, an IAM
   grant, a seed script, and — worst — a second thing called "the registry" that a reader has to
   check the caching rules of. A constant cannot be flipped by whoever holds Firestore write
   access, which is the property that matters for a field the risk table trusts.
2. **`base[action_class]` stays in item 7 so the determinism boundary has one address.** The
   tempting shape is a `Tool` carrying its own base score, since it is per-action-class the way
   the other three fields are. But §4.2 is one formula over four lookups, and ADR-003's whole
   claim is that risk is "a pure function of the typed action, computed by table lookup" that a
   judge can read in one place. Splitting one component into the module that also validates
   makes it possible for the two to disagree, and makes "where does risk come from" a
   two-file answer. `tests/test_action.py` asserts `Tool` has exactly four fields, so the drift
   fails the build rather than being noticed in Phase 8.
3. **`params` would be a typed channel onto the object the boundary is a function of.** §4.2
   writes the worked example as `ROLLBACK_CONFIG(inventory-api, v42→v41)`, which reads like the
   Action needs to carry the versions. It does not: `Service.known_good_version` and
   `current_config_version` already exist in the entity model (item 4 put them there), so item
   10's executor derives the rollback target from data the Planner does not control. Adding a
   ninth field would give an LLM a validated-but-open dictionary on the *one* object the gateway
   scores — every other field is checked against an authority, and `params` by construction
   could not be. §3 says "don't invent variants"; this is the variant worth not inventing.
4. **Raising is what makes stage 1 fail closed, exactly as in ADR-010 reason 1.** A
   `-> Action | None` is one forgotten `if action:` away from the gateway scoring something that
   was never validated — and unlike a bad registry read, there is no later stage that would
   catch it, because every later stage assumes a well-formed typed object. `NotATypedAction`,
   `UnknownTool`, `UnknownTarget` and `FieldMismatch` share one base item 7 catches once and
   maps to `DENY(stage="schema")`, the stage `telemetry.AuthStage` already reserves. A
   reflection test rejects any optional-`Action` or optional-`Tool` return. `validate()` accepts
   `object` rather than `dict` for the same reason: §10 names free-form text as a case, and it
   is only a case if a bare string can actually be handed in.
5. **No span here, and no state here.** A validation is a data check, not a decision — the same
   line ADR-010 drew when it left the `authorization.decision` span to item 7, which emits it
   carrying the standing it read. Emitting at stage 1 would also mean inventing values for
   `standing`, `target_tier`, `blast_radius` and `reversible`, which for a malformed action are
   precisely the things that do not exist. Likewise `outcome_for()` is a function, not a
   counter: §7.1 is explicit that "no agent owns its own iteration count — the control loop
   does, in code", so item 9's loop keeps the count next to its `REFUTED` retry budget and this
   module owns only the arithmetic — the same split `registry.degraded_by_window()` used.
6. **Synchronous, because it does no I/O.** The project convention is async throughout, and
   `registry.py` is async because Firestore is. `validate()` reads two frozen tuples. `async`
   would add an `await` at every call site and an `asyncio.run()` to every test in exchange for
   nothing, and it would imply an I/O boundary at the one stage that deliberately has none.

**What this deliberately does not do:** score risk (item 7 — this module produces the typed
object the table is a function of, and asserts the two §4.2 worked examples validate clean so
item 7 inherits known-good inputs), verify identity or `proposed_by` against the registry (§2.1
stage 2/3), check `evidence_refs` against an evidence store (item 12 owns it; shape only here),
emit any span, expose an HTTP route, or execute anything. It also closes one thing ADR-010 left
open: a test now asserts every `tool_scope` string in `registry.AGENTS` names a real `TOOLS`
entry, so the two bare strings item 5 seeded are honoured rather than assumed.

**Revisit when:** a tool's schema must change without a deploy — an operator disabling an action
class during an incident, say — at which point `target_kind`/`reversible`/`blast_radius` stay
constants and only an enabled/disabled bit moves to Firestore, because that is the only part
that is genuinely operational state.

**Alternatives considered:** the tool registry in Firestore with a request-time read API
mirroring item 5 (rejected in reason 1); `base_risk` on the `Tool` record (reason 2); a `params`
field validated against a per-tool parameter schema — the most literal reading of "declared
fields validated against the tool schema" (reason 3); `validate()` returning a
`ValidationResult(outcome, reason, action | None)` instead of raising (reason 4 — it reintroduces
the optional shape item 5 banned); a stateful `MalformedBudget` object keyed by incident
(reason 5 — it puts the count in the module §7.1 says must not hold it); one generic
`_enum(data, key, allowed)` helper instead of `_check_tier` / `_check_blast_radius` (rejected —
mypy-strict cannot narrow a TypeVar to the Literal, and `registry._check_standing` had already
set the monomorphic precedent); a single flat `InvalidAction` with a reason string (rejected —
the four subclasses let item 7 and item 9 distinguish "the Planner lied about reversibility"
from "the Planner emitted prose", which are different failures with different remedies).
