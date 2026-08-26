# ADR-012 — The gateway: the agent signs, RBAC and ABAC split, and a Decision of our own

**Status:** Accepted (revisit when audit signatures must survive a process restart)

**Decision:** `provenance/gateway.py` is `ARCHITECTURE.md` §2.1's pipeline and `authorize()` is
its only entry point; it takes an untrusted `object` and runs schema validation itself.
`provenance/risk.py` holds §4.2's table including `base[action_class]`;
`provenance/credentials.py` mints and verifies §2.1 stage 2's assertion. The **agent** signs its
own credential and the gateway verifies against the registered `public_key`; the TTL is 300
seconds. Stage 4 is two checks — tool scope by membership (RBAC), standing through PortunusMCP's
`abac` primitives (ABAC). A `DEGRADED` agent's proposal is scored and then held; a `SUSPENDED`
agent's is denied unscored. `authorize()` returns a frozen `Decision` of our own, signed with an
ephemeral per-process key, and the `authorization.decision` span's fields below `agent.{id,
version}` were made optional so that pre-standing denials still reach the audit stream.

**Reasoning, in order of weight:**

1. **"Minted by the registry and verified against the agent's `public_key`" cannot both be
   true, and the resolution is the one with the real security property (primary reason).**
   Verifying against the *agent's* public key requires signing with the *agent's* private key,
   but ADR-010 deliberately stores no private halves — `seed_registry.py` prints each once and
   forgets it, and rejected both a gitignored `.keys/` directory and Secret Manager for them.
   The alternative reading — one registry keypair signs every assertion, the gateway verifies
   against the registry's public key — leaves `Agent.public_key` with no consumer at all and
   makes a compromised agent indistinguishable from a healthy one, because the thing being
   proved would be "the registry exists" rather than "this agent holds its key". So the registry
   **issues and registers** the keypair (`--rotate` being the one path to a new one) and the
   agent signs. §2.1 carries a sentence saying so rather than being left ambiguous.
2. **The credential must be bound to the action, not merely presented alongside it.** §2.1 says
   only that identity is checked, which a literal implementation satisfies by verifying the
   signature and moving on. That leaves `Action.proposed_by` unchecked: an authenticated agent
   could present its own valid credential beside an action attributed to another agent, and
   every later reader of `proposed_by` — item 14's standing arithmetic, the ledger, item 28's
   panel — would be looking at the wrong identity. So the gateway denies unless `proposed_by`
   equals the credential's `agent_id@agent_version`, and denies a credential minted for a
   superseded version, or rotation would revoke nothing. Both deny as `CREDENTIAL_INVALID`
   rather than earning new reasons: they are one failure — this credential does not
   authenticate this proposal.
3. **RBAC and ABAC are two mechanisms, and Portunus's grammar says so.** `abac.compile_condition`
   whitelists comparisons and `and`/`or`/`not` over dotted paths under a fixed
   `{identity, tool, context, risk}`; it has no `in` operator. Tool scope is a membership test —
   that is what role-based means — and expressing it through ABAC would mean synthesising an
   OR-chain from a list at every authorization to do what `in` already does, which is a string
   builder on the authority path. The standing rule *is* attribute-based and maps onto
   `identity.standing` exactly, so it is genuinely compiled and evaluated by the library, which
   is what ADR-004's "PortunusMCP supplies RBAC/ABAC primitives" disclosure claims. A test
   asserts the compiled `abac.Condition` object rather than the behaviour, so a reimplementation
   that quietly stopped using the dependency would fail the build.
4. **A DEGRADED hold is scored; a SUSPENDED denial is not.** §2.1 says "the earliest terminal
   outcome wins", which read literally terminates both at stage 3 with no arithmetic. But item
   31's approval card renders the component-by-component breakdown for everything a human is
   asked to approve, and §3.4's rule is "held **regardless of** risk score" — a sentence that
   only means something if the score exists. "Held despite scoring 2" is precisely item 28's
   beat. A denial is different: nobody is being asked to weigh anything, §8.1 wants the span to
   carry no score, and computing one would suggest the number was involved. So the stage stays
   `registry` (the honest cause) and only the score rides along.
5. **Our own `Decision`, not Portunus's.** ROADMAP item 0.5 left this open: map
   `hold → human_approval_required` and ignore `challenge`, or define our own. Portunus's
   vocabulary cannot express §4.2's APPROVE vs APPROVE_NOTIFY split — the 0–3 and 4–6 bands would
   collapse to one value — and carries `challenge`, which this system has no concept of.
   `telemetry.AuthOutcome` and `AuthStage` had already fixed the vocabulary in item 2, so the
   `Decision`'s fields are typed *with those Literals*, and the returned object cannot hold an
   outcome its own span would refuse to emit. It also keeps a pydantic model off the authority
   path. Portunus's `decision` module stays pinned by `tests/test_portunus_surface.py` so an
   upstream change is still visible.
6. **A `subject` field, so the signature is bound to what it decided.** Signing only
   `(outcome, stage, reason, score)` would let a signed APPROVE be lifted from a rollback onto a
   compliance-check disable — the components would match and the signature would verify. The
   `subject` is `agent@version|action_class|target`, taken from the *credential* rather than
   `proposed_by` because the credential is the authenticated half, and it makes
   `verify_decision(decision, pem)` checkable from the `Decision` alone.
7. **The span shape widened rather than a fifth shape appearing.** A schema denial has no
   validated action and a registry-failure denial has no standing, so neither could open the
   span as item 2 wrote it — yet §2.1 stage 6 says every outcome including denials is signed
   into the audit log. The three options were: drop those spans (two denial classes vanish from
   the one stream §8 promises), add a fifth shape (§8.1's four-shape contract becomes five and
   the ledger UI merges two streams), or make the fields optional. The last is smallest and
   loses nothing: `_set_attributes` already omits `None`, so absent means *omitted* rather than
   emitted empty, and out-of-vocabulary values still raise. Module, §8.1 and
   `tests/test_telemetry_schema.py` moved together, which is the condition item 2 set.
8. **The signing key is ephemeral per process, and that is a marked shortcut.** ADR-010 already
   declined both places a persistent private key could live. The property that matters for the
   demo and for a judge — a decision in the stream verifies against `public_key_pem()` from the
   same run — holds, and CI and local runs need no secret. What is lost is verification across a
   Cloud Run restart. A `ponytail:` comment in `gateway.py` names the upgrade path (a PEM from
   Secret Manager, keeping generation as the fallback). `THREAT_MODEL.md` records the limitation
   rather than the code implying a durability it does not have.
9. **`authorize()` takes `object`, and that is §1.1 property 1 made structural.** Handing it a
   pre-validated `Action` would make `DENY(stage="schema")` unreachable and let a caller that
   forgot to validate reach the risk table with unchecked fields. Because the only door does both,
   there is no way to score something that was never validated. Every terminal outcome is a
   returned `Decision`, never a raised exception, because an exception is something a caller can
   swallow into "nothing happened" — and a swallowed denial is an unrecorded one.

**What this deliberately does not do:** execute anything (an APPROVE is a return value; item 10
owns the executor), park a held incident (§2.1 stage 7 → `approvals.park()`, called by `incident.py`; item 30's `resolve()` is a second door *here*, and [`ADR-032`](./ADR-032-the-approval-queue.md) says why it had to be), keep
the malformed-retry count (`action.outcome_for()` already ships that stateless for item 9's
control loop), expose an HTTP route (§2.1 is a pipeline, not an endpoint — ADR-008, and
`app.py`'s docstring), or render the ledger (item 11).

**Revisit when:** audit signatures must survive a process restart (reason 8), or a second
attribute condition appears — a maintenance window, a change freeze — at which point the ABAC
half earns the `context` root Portunus already reserves and the conditions move onto the registry
record instead of being one compiled constant.

**Alternatives considered:** one registry keypair signing all assertions (reason 1 — it orphans
`Agent.public_key`); folding `proposed_by` verification into item 9 (reason 2 — it is an identity
check and belongs at the identity stage); routing tool scope through `abac` as a synthesised
OR-chain (reason 3); dropping `abac` entirely for two `if` statements (reason 3 — it would leave
Portunus contributing only `signing`, making ADR-004's RBAC/ABAC disclosure rest on a pinned
import); terminating a DEGRADED hold at stage 3 unscored (reason 4); returning Portunus's
`decision.Decision` with `hold → human_approval_required` (reason 5); signing only the verdict
without a subject (reason 6); a fifth `provenance.authorization.rejection` span, or emitting no
span at all before standing is known (reason 7); a Firestore-stored or Secret-Manager gateway
keypair (reason 8 — both were declined for agent keys in ADR-010 and are no better here for a
key that only has to outlive one run); `authorize(action: Action, ...)` (reason 9); a 60-second
or 900-second credential TTL (300 is short enough for "short-lived" to be a real claim and long
enough that a paused demo take does not produce a spurious identity denial).
