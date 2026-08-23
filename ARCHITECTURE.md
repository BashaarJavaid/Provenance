# Architecture

The full design for Provenance: both decision pipelines, every component in depth, the determinism boundary, the memory model, failure modes, observability, testing strategy, and deployment. Read [`README.md`](./README.md) first for the pitch and the high-level diagram; read [`THREAT_MODEL.md`](./THREAT_MODEL.md) for what this design does and does not protect against; read [`docs/adr/`](./docs/adr/) for why several common alternatives weren't chosen.

---

## 1. High-level flow

Two nested loops, applied uniformly regardless of domain:

**The action loop** (any single agent proposal):

```
PROPOSE → AUTHORIZE → EXECUTE → VERIFY → REMEMBER
```

**The incident loop** (any detected deviation):

```
OBSERVE → DIAGNOSE → PROPOSE → AUTHORIZE → EXECUTE → VERIFY → LEARN
                          ↑                                  │
                          └────── retry (bounded) ───────────┘
                                                             │
                                                    escalate to human
```

Agents propose. A deterministic policy layer decides. Systems execute. Verification proves or refutes the outcome. Memory learns only from what was confirmed.

The recursion is the idea: the memory write path *is* the action loop, applied to the system's own beliefs. A probabilistic component recommends; a deterministic component decides. The full component diagram is in the [`README.md`](./README.md) Architecture section (single source; not duplicated here).

### 1.1 The four load-bearing properties

These are non-negotiable in implementation. Any change that would violate one of them is wrong, no matter how convenient:

1. **There is no direct path from any reasoning agent to a state-mutating action.** The gateway is architecturally the only path. If a second path exists, the security story collapses.
2. **The memory write path mirrors the action path exactly.** Probabilistic recommends, deterministic decides — for beliefs as for actions.
3. **No LLM-generated number is an input to a deterministic decision.** Confidence is computed from evidence structure (§4.3); risk is a table lookup (§4.2). This is what separates a real determinism boundary from a cosmetic one.
4. **The registry is read at request time, not at boot.** An agent's standing can change mid-run and the next authorization reflects it.

## 2. Decision pipelines

Two pipelines, one shape. Both consume typed objects, both read the registry live, both produce signed, auditable decisions, and neither accepts a model-generated number as input.

### 2.1 The action pipeline (Agent Gateway)

Every state-mutating proposal passes through these stages in order; the earliest terminal outcome wins:

1. **Schema validation** — the typed action's `action_class` must exist in the tool registry, its target must exist in the entity model, and its declared fields must validate against the tool schema. A fabricated tool, a nonexistent target, or free-form text is rejected mechanically (§7.1).
2. **Identity** — the proposing agent presents a short-lived credential: an ECDSA-signed assertion `(agent_id, agent_version, issued_at, expires_at)` minted by the registry and verified here against the agent's registered `public_key`. Signature or expiry failure is a terminal denial. No shared service accounts. Minting and verification are new code in this repo, built on PortunusMCP's `signing` primitives; Portunus's own identity broker (static API keys, HMAC) is not used.
3. **Registry read (request-time)** — identity, version, tool scope, standing. An agent with `standing: DEGRADED` has every proposal held for human approval regardless of risk score; `SUSPENDED` is denied outright.
4. **RBAC/ABAC** — is this action class within this agent's declared tool scope?
5. **Deterministic risk scoring** — the table lookup in §4.2. Never a model opinion.
6. **Outcome** — `0–3` auto-approve; `4–6` auto-approve with notification; `7+` HOLD for human approval. Every outcome is ECDSA-signed into the audit log, including denials.
7. **Hold/resume** — a held action parks the incident; the approval card (§8) lands in the store operations manager's queue; the incident resumes on approve/deny via the ADK Task API.

**As built (item 7).** `provenance/gateway.py` is this pipeline and `authorize()` its single entry point; `provenance/risk.py` is §4.2's table and `provenance/credentials.py` stages 1–2's assertion. Five things the implementation settled that the list above left open:

- **The agent signs its own assertion.** "Minted by the registry and verified against the agent's registered `public_key`" only reconciles one way: verifying against the *agent's* public key requires the *agent's* private key, and `scripts/seed_registry.py` prints each private half once and stores it nowhere (ADR-010). So the registry **issues and registers** the keypair — `--rotate` being the one path to a new one — and the agent holds the private half and signs. What the gateway checks is possession of the key matching the record it just read, which is the property that matters.
- **The registry read physically precedes stage 2**, because the public key stage 2 verifies against is a field on the record stage 3 fetches. The `stage=` recorded on a denial is still §2.1's, so the audit stream reads the way this list does.
- **Stage 4 is two checks, because RBAC and ABAC are two things.** Tool scope is role-based and is a membership test. The standing rule is attribute-based and is compiled and evaluated by PortunusMCP's `abac` primitives; its condition grammar has no `in` operator, so routing scope through it would mean synthesising an OR-chain to do what `in` does.
- **A DEGRADED hold is scored anyway.** It terminates at stage 3 by cause — `HOLD, stage="registry", reason="STANDING_DEGRADED"` — but the §4.2 arithmetic rides along, because item 31's approval card renders the component breakdown for everything a human is asked to approve, and "held despite scoring 2" is the sentence item 28's beat needs. A `SUSPENDED` denial carries no score: a denial owes the human no arithmetic.
- **The credential lifetime is 300 seconds** (`credentials.CREDENTIAL_TTL_SECONDS`), a number no document previously carried — the same gap §3.4's rolling window had before item 5.

The gateway returns its own frozen `Decision` (outcome, stage, reason, subject, score, signature), not PortunusMCP's `decision.Decision`: that vocabulary is allow / deny / challenge / human_approval_required, which cannot express §4.2's APPROVE vs APPROVE_NOTIFY split and carries one value this system has no concept of. Reasoning in `docs/adr/ADR-012`.

### 2.2 The memory write pipeline (Memory Policy Engine)

The mirror. Every proposed belief commit passes through:

1. **Typed-evidence validation** — every evidence item must be a well-formed `Evidence` object (§3.3); the recommendation must reference existing evidence IDs.
2. **Registry read (request-time)** — the proposing agent must hold registry authority for that memory domain, with standing ≥ GOOD. A DEGRADED agent's memory writes are rejected outright.
3. **Novelty check (mechanical)** — evidence is *new* to a belief iff its `(source_id, observed_at)` pair does not already appear in that belief's history. No model judgment involved.
4. **Confidence computation** — the published noisy-OR formula in §4.3, over the typed evidence. The Analyst's asserted confidence, if it ever asserts one, is discarded.
5. **Threshold + conflict rule** — 0.50 for a new belief; 0.70 **plus the different-source-class rule (§6.3)** for a status flip.
6. **Outcome** — COMMIT (new version, supersession link, signature), REJECT (logged, standing counter incremented), or RETRACT (§6.4). Every outcome is signed and audited.

**As built (ROADMAP item 13), stages 3 and 4.** Novelty compares `(source_id, observed_at)` pairs resolved from the `evidence/{id}` documents the current version cites — the pair, not the id and not the payload, so a duplicate cannot be renamed past the check. A proposal against an **existing** belief carrying nothing novel is `REJECT("NO_NEW_EVIDENCE")`, refused at stage 3 before the arithmetic runs; a first belief has no history to be novel against, so an evidence-free first claim is refused by stage 4 at confidence 0.00 instead. Stage 4 computes over the **accumulated** evidence set: a superseding version cites its predecessor's evidence plus the novel items, as §3.2 renders it. Reasoning in [`docs/adr/ADR-017`](./docs/adr/ADR-017-novelty-and-the-accumulated-evidence-set.md).

**As built (ROADMAP item 14), stages 5 and 6.** Which threshold a proposal faces is decided by one mechanical fact — whether its status differs from the version in force — and never by a judgment: 0.50 for a new belief or a re-affirmation, 0.70 for a flip. §6.3's corroboration requirement is a **set difference over source classes**: a flip commits only if its novel evidence contributes a class the accumulated set does not already carry, which is read from the same `evidence/{id}` documents stage 3 already resolved. The two ways a flip can fail keep their own names — `BELOW_THRESHOLD` carrying `threshold = 0.70` when the number is what stopped it, `FLIP_UNSUPPORTED` when the corroboration is. Stage 6's "standing counter incremented" is a real write: `BELOW_THRESHOLD`, `FLIP_UNSUPPORTED` and `NO_NEW_EVIDENCE` — the refusals that are statements about the proposing agent's evidence — append to its `rejection_window`, and the third inside §3.4's window writes `DEGRADED`. Infrastructure refusals do not, because standing has no automatic restoration path and an outage is not the agent's doing. Reasoning in [`docs/adr/ADR-018`](./docs/adr/ADR-018-the-conflict-rule-and-the-standing-counter.md).

## 3. Canonical typed objects

Four object shapes carry all authority-relevant data. Don't invent variants — a new endpoint or agent reuses these shapes.

### 3.1 The typed Action

The Remediation Planner's only output format. Never free-form text.

```
Action {
  action_class,        # must exist in the tool registry
  target,              # must exist in the entity model
  target_tier,         # tier1 | tier2 | tier3 (validated against entity model)
  blast_radius,        # single-service | multi-service | org-wide
  reversible,          # true | effects-irreversible
  evidence_refs,       # [evidence IDs grounding the diagnosis]
  success_predicate,   # declared BEFORE execution; what verification checks
  proposed_by,         # agent id + version
}
```

`reversible` and `blast_radius` are declared by the Planner and **validated against the tool schema** — the tool registry knows that `DISABLE_COMPLIANCE_CHECKS` is irreversible and org-wide, so a Planner claiming otherwise fails validation. Not vibes.

The tool registry is `provenance/tools.py`: an in-code frozen constant, not a Firestore
collection. A `Tool` carries four fields — `action_class`, `target_kind` (`service` |
`supplier`, which selects the entity collection the target must be found in), and the
authoritative `reversible` and `blast_radius`. It deliberately does not carry
`base[action_class]`; every risk component lives together in §4.2's table. Standing is read at
request time because it changes mid-run (§1.1 property 4); a tool's reversibility does not
change at all, which is why this registry is a constant and the agent registry is not.

`provenance/action.py` holds the Action itself and `validate()`, which turns an untrusted
proposal into a typed Action or raises. **There is deliberately no `params` field.** §4.2 writes
the worked example as `ROLLBACK_CONFIG(inventory-api, v42→v41)`, but the versions are not the
Planner's to choose: the executor reads `known_good_version` off the service in the entity
model. An open parameters field would be a typed channel an LLM could put anything through, on
the one object the whole determinism boundary is a pure function of. Schema reasoning in
[`docs/adr/ADR-011`](./docs/adr/ADR-011-tool-registry-and-action-validation.md).

### 3.2 The Belief object

```
Belief #42
Scope:       ENTITY                  # ENTITY | CLASS
Entity:      SUP-042 (Supplier X)
Domain:      supply_chain
Status:      AT_RISK                 # domain-typed; UNKNOWN and RETRACTED are universal
Confidence:  0.94                    # COMPUTED (§4.3) — never asserted
Evidence:    [ev-118, ev-140, ev-141]
Authority:   supply-chain-agent@v3 (standing: GOOD) + compliance-feed
Committed:   2026-08-20T14:02Z  by memory-policy-engine  (sig: ecdsa:…)
Decay:       half_life=30d  expires=2026-09-20  on_expiry=REVERIFY
Supersedes:  Belief #17
History:
  #17  Aug 12  FLAGGED   conf 0.71  ev-[118]           → superseded by #42
  #42  Aug 20  AT_RISK   conf 0.94  ev-[118,140,141]   → current
```

Beliefs are append-only versioned: supersession links, never overwrites, never deletion. A `CLASS`-scope belief additionally carries `class`, `statement`, `derived_from` (constituent entity-belief IDs), and a hard `use: ADVISORY_ONLY` cap (§6.2).

### 3.3 Typed Evidence

```
Evidence {
  id, source_id, source_class, observed_at, ingested_at,
  payload_hash, verifiable_by          # how a third party could re-check this
}
```

`source_class` ∈ { `verified_system_observation`, `third_party_audit`, `contractual_record`, `agent_inference`, `unverified_external_claim` }.

Typing the evidence is what makes everything downstream mechanical: novelty is a `(source_id, observed_at)` set-membership check, confidence is a formula over source classes, and the conflict rule compares source classes — no model judgment anywhere in that chain.

### 3.4 The Agent registry record

```
Agent {
  id, version, public_key,
  tool_scope:      [ …allowed tool IDs… ],
  memory_domains:  [ …domains it may write beliefs in… ],
  standing:        GOOD | DEGRADED | SUSPENDED,
  rejection_window: [ …recent rejected write attempts… ]
}
```

**Standing is earned and lost.** Three rejected memory writes lacking verifiable evidence inside the rolling window → standing drops to `DEGRADED`. The window is **3 rejections inside 24 hours** (`registry.REJECTION_THRESHOLD` / `registry.REJECTION_WINDOW_HOURS`); each `rejection_window` entry carries `rejected_at` and `reason`, so the counter is the list's length and the panel can show the cause. A `DEGRADED` agent's proposals require human approval **regardless of risk score**, and its memory writes are rejected outright. Restoration requires explicit human reinstatement; the system never quietly forgives. This closes the loop on the poisoning attack: repeated attempts *change what that agent is permitted to do*.

Stored as one flat document per agent at `agents/{id}`, with `version` as a field, read fresh on every authorization (§1.1 property 4). The stored `standing` is authoritative — it is never recomputed from `rejection_window`, because `SUSPENDED` is not derivable from rejections and reinstatement needs a field a human can set. The Policy Engine writes `DEGRADED` through `registry.record_rejection()` (item 14); a human writes the rest. The window is append-only and never pruned — `degraded_by_window()` filters by cutoff on read, and an entry that has stopped counting is still the record of why an agent degraded. A reinstatement that does not also clear the window will re-degrade on the next single rejection inside 24 hours. Schema reasoning in `docs/adr/ADR-010`.

## 4. The determinism boundary

This section exists because it is the most common place these architectures quietly cheat: authority is moved into code in the diagram while the code's decisive input remains an LLM's opinion.

### 4.1 The rule

A deterministic decision may consume: typed data, cryptographic identity, registry state, and numbers computed by published formulas. It may **not** consume a number an LLM produced. An LLM's role ends at *extraction* and *recommendation*.

### 4.2 Risk scoring — a table, not a judgment

Risk is a pure function of the typed action, computed by lookup:

```
risk = base[action_class]
     + criticality_points[target_tier]        # tier1 +2, tier2 +1, tier3 0
     + blast_points[blast_radius]             # org-wide +2, multi-service +1, single +0
     + irreversibility_points[reversible]     # effects-irreversible +3, reversible +0

0–3  → auto-approve
4–6  → auto-approve with notification
7+   → HOLD for human approval
```

Worked examples, so demo outcomes are principled rather than convenient:

| Action | base | crit | blast | irrev | total | outcome |
|---|---|---|---|---|---|---|
| `ROLLBACK_CONFIG(inventory-api, v42→v41)` | 1 | +1 | +0 | +0 | **2** | auto-approve |
| `DISABLE_COMPLIANCE_CHECKS(SUP-042)` | 4 | +2 | +2 | +3 | **11** | human approval required |

Disabling a compliance control scores high because it mutates a safety control, on a tier-1 target, org-wide, and the transactions that occur while it is off cannot be un-occurred. Rollback scores low because it is a reversible, single-service change to a known-good prior state.

**As built (item 7).** `provenance/risk.py`. The three point tables above are enumerated in full by this section; `base[action_class]` was not, and now has one address: `risk.BASE` — `ROLLBACK_CONFIG` 1, `DISABLE_COMPLIANCE_CHECKS` 4, the two values the worked examples fix by arithmetic. It lives here rather than on `tools.Tool` so a change to the table is a change to one file (ADR-011). A test asserts `set(risk.BASE)` equals the set of `tools.TOOLS` action classes, so a third tool cannot ship without a base score and fail at authorization time instead of at build time.

`score()` takes a validated `Action` and nothing else — no confidence, no model output, no free parameter — which is §4.1's rule made structural rather than documentary. `band()` returns `APPROVE`, `APPROVE_NOTIFY` or `HOLD` and **never `DENY`**: every denial in the system comes from *who is asking* (identity, registry standing, tool scope), and the score's worst possible answer is "a human decides". `tests/test_risk.py` sweeps all 2 × 3 × 3 × 2 = 36 combinations — §10's Risk-table row — because a lookup with a hole is a crash at authorization time, not a wrong number.

### 4.3 Confidence — computed, not asserted

Noisy-OR over independent evidence, weighted by source class and decayed by age:

```
w_i  = base_weight[source_class_i] × 2^(-age_i / half_life_domain)
conf = 1 − Π(1 − w_i)      over the *distinct source classes* present
```

```
base_weight:
  verified_system_observation  0.60
  third_party_audit            0.55
  contractual_record           0.50
  agent_inference              0.15
  unverified_external_claim    0.00

half_life_domain:              30 days, every domain
```

The half-life is published here for the same reason the weights are ([`ADR-002`](./docs/adr/ADR-002-computed-confidence.md)): the defense of these numbers is that they are inspectable and fixed, not that they are optimal, and one that appeared in no document was neither. It is a single number until a second domain writes beliefs (ROADMAP item 21).

Three properties fall straight out of the arithmetic, with no LLM in the loop:

- **A bare assertion cannot move confidence at all.** `unverified_external_claim` has weight 0.00, so the poisoning defense (§6.3) is *arithmetic*, not a model's opinion about whether something smells adversarial.
- **Corroboration must be independent.** Only distinct source classes combine, so an agent cannot inflate confidence by restating the same observation five times.
- **Beliefs weaken on their own.** Age decays every weight, so an unre-confirmed belief drifts toward the threshold and eventually trips the Sweeper (§6.5).

Commit threshold: 0.50 for a new belief; **0.70 plus the source-class rule in §6.3 for a status flip.**

**As built (item 14).** Note what the two numbers imply together: the strongest base weight is 0.60 and the formula collapses a class to its least-decayed item, so **no single source class can ever reach 0.70**. A flip therefore only ever passes the number by resting on the accumulated evidence set (§3.2) — which is exactly the case where §6.3's class rule is the only thing left standing, and the reason the two halves of the flip door were built in one item.

### 4.4 Where each decision actually lives

| Decision | Made by | Input it is forbidden to use |
|---|---|---|
| Does this action execute? | Gateway **[CODE]** | The proposal's persuasiveness or stated urgency |
| How risky is this action? | Risk table **[CODE]** | Any model-generated score |
| Is this evidence sufficient? | Policy Engine **[CODE]**, via computed confidence | Any model-asserted confidence |
| Does this belief supersede that one? | Policy Engine **[CODE]**, via the standing + novelty rule | The Analyst's preference |
| What does this messy input *say*? | Sanitizer / Analyst **[LLM]** | — (extraction is the right job for a model) |

## 5. Component responsibilities

Probabilistic components are **[LLM]**; authority components are **[CODE]**; managed Google Cloud services are **[SERVICE]**. No component is both probabilistic and authoritative.

### 5.1 Model Armor **[SERVICE]**

Google's managed inline guardrail: template-configured prompt-injection/jailbreak detection and Sensitive Data Protection screening (150+ PII infoTypes) on all inbound content, verdicts logged to Cloud Logging. **First filter — never the boundary.** The design assumes it leaks (see [`THREAT_MODEL.md`](./THREAT_MODEL.md)); the demo shows it leaking.

### 5.2 Ingestion & Sanitizer **[LLM]** — Gemma 4, isolated

Reduces raw inbound data to typed facts; tokenizes PII that survived Model Armor. Runs on a small, isolated open model served via Vertex AI Model Garden — untrusted content never reaches a frontier model raw. Its output is data, never authority: a fact it emits can inform a diagnosis but cannot authorize anything.

### 5.3 Orchestrator **[LLM]** — Gemini 2.5 Pro, ADK Graph Runtime

Classifies the deviation, recalls entity-level *and* class-level beliefs (§6.6), routes to domain agent(s). Wake-on-event against the live trigger stream.

**As built (item 9).** The trigger stream is `POST /trigger` on the Cloud Run service, guarded by a shared-secret header — a Firestore listener would need an always-warm instance the cost ceiling forbids (`docs/adr/ADR-013`). Of the three verbs only *classify* is reasoning and lives in `provenance/agents/orchestrator.py`; recall is a store lookup and routing is a table lookup, and both are deterministic code in `provenance/incident.py`, where they can be tested. The whole loop is an ADK `Workflow` — ADR-007's Graph Runtime, taken literally — in which §7.1's one re-plan is an actual edge back to the Planner. Recall returns empty until item 16. The Orchestrator holds no registry record: it proposes no action and writes no belief, so §3.4 has nothing to record about it.

### 5.4 Domain agents **[LLM]** — Gemini 2.5 Pro

- **SRE/Infra Agent** — diagnoses infra anomalies against prior belief; proposes remediation.
- **Supply-Chain Agent** — diagnoses supplier/inventory disruption against prior belief; proposes mitigation.

Adding a domain must cost one agent file and one registry entry, and zero lines in the gateway, risk table, Policy Engine, Sweeper, or orchestrator — this is instrumented and reported as the generality proof (spec §18; ROADMAP Phase 6).

### 5.5 Remediation Planner **[LLM]** — Gemini 2.5 Pro

Converts a diagnosis into exactly one typed Action (§3.1) with declared blast radius, reversibility, evidence references, and a success predicate. Never free-form text. A malformed emission is returned once; a second malformed emission escalates the incident (§7.1).

**As built (item 9).** "Never free-form text" is structural, not instructed: the agent carries an ADK `output_schema`, so the response is constrained to §3.1's eight fields and prose is not an available answer. What it emits is still only a proposal — `action.validate()` overrules the declared tier against the entity model and the declared reversibility and blast radius against the tool registry, so understating any of the three fails validation rather than lowering the score. The retry count lives on the control loop's state, never on the agent.

**The predicate floor (item 11.5).** The Planner is told the target's **nominal error rate** — read off the entity model in `_seed_state()`, in both units (`0.01 (1%)`) — and the declared threshold must sit *strictly above* it. This is not tidiness: `executor.execute()` writes `service.error_rate` back verbatim on a successful rollback, so a threshold *at* nominal is unsatisfiable no matter how well the remediation worked, and §7.2's `REFUTED` is the honest answer to it. Found live, not designed — one run in three declared "less than 1%" against a service whose healthy rate is exactly `0.01`. The fix is deliberately upstream: **§3.1 is unchanged and `success_predicate` stays free text**, because a typed threshold field is exactly the `params` ADR-011 removed, and judging a natural-language claim is §5.8's job. Loosening the Verification Agent to accept a boundary miss was rejected outright — that would trade the property Phase 5 exists to demonstrate for a greener demo.

### 5.6 Agent Registry **[CODE]**

Source of truth for identity, version, tool scope, memory-domain authority, and standing (§3.4). Read on **every** authorization by both the Gateway and the Memory Policy Engine — request time, not boot time.

### 5.7 Agent Gateway **[CODE]** — built on PortunusMCP primitives

Identity → RBAC/ABAC → deterministic risk table → sign → approve / hold-for-human / deny (§2.1). Architecturally the only path from any agent to a state-mutating action. PortunusMCP is consumed as a library dependency for three modules only — `signing` (ECDSA), `abac` (condition grammar), `decision` (typed models) — see [`docs/adr/ADR-004`](./docs/adr/ADR-004-portunusmcp-as-library.md) and the item-0.5 done-note in [`ROADMAP.md`](./ROADMAP.md); identity resolution and credential minting, the risk table, typed-action fields, registry-standing reads, and hold/resume path are new code in this repo.

### 5.8 Verification Agent **[LLM]** — Gemini 3.5 Flash

Returns exactly one of `CONFIRMED` / `REFUTED` / `INCONCLUSIVE` against the action's **pre-declared** success predicate (§7.2). High-throughput, lower-stakes — which is why Flash.

**As built (item 10).** `provenance/agents/verification.py`, with an ADK `output_schema` so the three-valued answer is structural rather than instructed. It is given **no tool and no store access**: the post-execution error rate and config version reach it as session state, put there by a fresh `executor.read_state()` read, because an agent that can fetch its own evidence can fetch until the evidence agrees with it. Like the Orchestrator it holds no registry record — it proposes no action and writes no belief, so §3.4 has nothing to record about it; its spans carry `verification-agent@v1`. The span it is judged on is opened by the control loop's `resolve` node rather than by the agent, because `verification.belief_written` is not known until the commit has been attempted — which is also what nests `belief.commit` inside `verification.outcome`. An exception out of the agent is `INCONCLUSIVE` (§7.3), emitted by the control loop, so a failed verification and a hedged one land in the same place. Reasoning in [`docs/adr/ADR-014`](./docs/adr/ADR-014-execution-and-the-stub-policy-engine.md).

### 5.8a Executor **[CODE]**

The box §1's diagram calls only "ACTUAL ACTION", named here because since item 10 something in this system actually mutates state. `provenance/executor.py` performs one authorized action and is **not a second path to one**: `execute()` re-verifies the `Decision`'s signature against the gateway's public key, requires an approving outcome, and requires `decision.subject` to name this action's class and target — so §1.1 property 1 is a property of the function rather than of which graph edge called it, and a signed APPROVE cannot be lifted from a cheap rollback onto an expensive action. It reads `known_good_version` off the **entity model**, never off the Action (§3.1 has eight fields and no `params` precisely so this is true), and reads the §9 `rollback_fails` switch out of Firestore at execution time so a fault stays flippable mid-incident (ADR-009). It emits no span: execution is not a decision, and what came of it reaches the trace through the verification span that judges it. Every failure raises `ExecutionError`, which the control loop turns into an escalation with nothing verified and nothing learned (§7.3).

### 5.9 Memory Analyst **[LLM]** — Gemini 2.5 Pro

Extracts typed evidence, detects semantic conflict with existing belief, proposes class-level generalizations. **Recommends — never commits, never asserts a confidence number.**

### 5.10 Memory Policy Engine **[CODE]**

The mirror of the Gateway, for beliefs (§2.2). Checks standing, domain authority, evidence novelty; *computes* confidence; versions, signs, commits or rejects or retracts. The actual authority over what the organization believes.

**As built (items 10, 12, 13 and 14).** `provenance/policy.py` runs all of §2.2 except `RETRACT`: the request-time registry read (standing must be `GOOD` **and** the domain must be in `memory_domains`; an unreadable registry is a `REJECT`, not a pass), the mechanical novelty check over `(source_id, observed_at)`, `confidence()` as §4.3's noisy-OR over distinct source classes with age decay across the accumulated evidence, **both** thresholds — 0.50 for a new belief or a re-affirmation, 0.70 for a status flip — **§6.3's different-source-class rule as a set difference over the classes the version in force rests on**, then sign and append a real superseding version through `provenance/beliefs.py`. A rejected write whose cause is the agent's own evidence increments its `rejection_window`, and the third inside §3.4's window writes `DEGRADED` — §2.2 stage 6, in full. What is deliberately absent: `RETRACT` (§6.4, item 15). The write is Firestore `create`, so a concurrent one loses rather than clobbers. Every outcome, refusals included, is signed and lands on a `belief.commit` span. Reasoning in [`docs/adr/ADR-014`](./docs/adr/ADR-014-execution-and-the-stub-policy-engine.md), [`ADR-016`](./docs/adr/ADR-016-the-versioned-belief-store.md), [`ADR-017`](./docs/adr/ADR-017-novelty-and-the-accumulated-evidence-set.md) and [`ADR-018`](./docs/adr/ADR-018-the-conflict-rule-and-the-standing-counter.md).

### 5.11 Staleness Sweeper **[CODE]**

Long-running async process: on belief expiry, re-verifies or downgrades to `UNKNOWN(stale)` (§6.5). One of the two async behaviours the track's runtime requirement asks for (the other is wake-on-event incident handling plus park/resume on human approval).

## 6. Institutional memory — design

Memory is a versioned model of what the organization currently believes, with full provenance. Not a log, not a vector index over history.

### 6.1 Entity beliefs

Recalled by exact key: a deviation on `inventory-api` reads the beliefs for `inventory-api`, mechanically. Versioned per §3.2 — supersession chain, history retained forever.

### 6.2 Class beliefs — what makes it learn, not memoize

Entity beliefs alone make the system a cache — it only helps on entities it has already seen. When ≥3 entity beliefs share a structural signature, the Analyst may propose a **CLASS** belief:

```
Belief #77
Scope:      CLASS
Class:      service.config_deploy
Statement:  Deploys altering connection-pool parameters on tier-2 services
            correlate with error-rate spikes within 10 minutes
Derived from: #42, #51, #63
Confidence: 0.61     # capped: max 0.75, always below its weakest constituent
Use:        ADVISORY ONLY
```

Class beliefs raise hypothesis priority for entities the system has **never seen**. They are hard-capped as advisory: a class belief may reorder what a domain agent investigates first; it may **never** be the evidence that authorizes an action or commits an entity belief. Generalization is allowed to make the fleet faster, never to make it more confident.

### 6.3 The conflict rule — one rule, three outcomes

A claim contradicting existing memory is neither auto-accepted nor auto-rejected. It is evaluated on **standing** and **evidence**:

- The proposing agent must hold registry authority for that memory domain, with standing ≥ GOOD.
- The claim must carry evidence that is **new** (mechanical novelty check, §2.2) and **verifiable**.
- **A status flip additionally requires at least one evidence item of a `source_class` different from the class that established the current status.** A single sensor cannot both set and clear an alarm.

Three cases, one rule:

- *Legitimate update.* Supplier X flagged Aug 1 on late shipments (`contractual_record`). Aug 15 it passes a compliance audit (`third_party_audit` — new, verifiable, different class). Confidence recomputes, threshold met → commit superseding version. The old version is never deleted; it remains the reasoning trail.
- *Poisoning attempt.* A compromised agent asserts "Supplier X is cleared" with no verifiable backing. Same rule: `unverified_external_claim` has weight 0.00, computed confidence does not move, no different-class corroboration → **rejected, logged, standing counter incremented.** The AT_RISK belief stands.
- *Disproven belief.* Retraction — see §6.4.

**As built (item 14).** "The class that established the current status" is the set of `source_class` values the version in force rests on — its accumulated evidence, already resolved by §2.2 stage 3 — and the rule is a set difference against it: a flip commits only if its novel items contribute a class that set does not carry. Because evidence accumulates, this is the stricter of the two readings available (it counts every class that has ever supported the belief, not only the one that last changed it), which is the right side to err on for a rule whose purpose is that one sensor cannot set and clear its own alarm. No model is consulted anywhere in it. Reasoning in [`docs/adr/ADR-018`](./docs/adr/ADR-018-the-conflict-rule-and-the-standing-counter.md).

### 6.4 Retraction is a first-class transition

A belief committed in good faith that turns out to be wrong is not silently overwritten. Retraction:

- requires evidence of a source class **at least as strong** as the class that established the belief,
- produces a `RETRACTED` version with a link to the disproving evidence,
- **flags every action previously authorized on that belief in the audit log for review.**

A system that can be wrong and knows which of its past decisions rested on the wrong thing is doing something no vector index can.

### 6.5 Decay, and something acting on it

`Valid until` is worthless if nothing consumes it. The Staleness Sweeper runs continuously:

```
on expiry:
  re-verification source available?
     yes → re-verify → CONFIRMED: new version, confidence refreshed, decay clock reset
                     → REFUTED:   retraction path (§6.4)
     no  → downgrade to UNKNOWN(reason=stale); belief stops informing hypotheses
           and is excluded from confidence computations. Never deleted.
```

An organization that cannot tell "we know this is fine" from "we last checked six weeks ago" does not have institutional memory. It has a log.

### 6.6 Recall — retrieval is an index, never the truth

Entity beliefs: exact key. Class beliefs: matching a novel deviation to a class statement is a similarity problem, and we use the standard tool — Vertex AI embeddings over belief statements, queried with the incident's typed facts.

The division of labor is strict, and it is the pre-emptive answer to "isn't this just RAG?": **semantic retrieval nominates candidates; the belief store decides what is true.** The index returns belief IDs and nothing else — it never sees confidence, status, or currency. The store resolves each ID to its current version, drops anything `RETRACTED` or `UNKNOWN(stale)`, and hands the Orchestrator the governed object with its computed confidence and provenance chain. The embedding is the card catalog. The library decides what's on the shelf. (See [`docs/adr/ADR-005`](./docs/adr/ADR-005-recall-index-nominates-store-decides.md).)

### 6.7 Storage

Firestore is the single store of truth: entity-keyed reads and append-only versioned writes are exactly the document-store access pattern. No second datastore unless a demo step needs a cross-dataset join; none does. (See [`docs/adr/ADR-001`](./docs/adr/ADR-001-firestore-single-store.md).)

**As built (ROADMAP item 12).** Three collections. A belief is a root document `beliefs/belief-{entity}` plus one **immutable document per version** at `beliefs/belief-{entity}/versions/{n}`, written with `create()` and never written again; evidence is normalised to `evidence/{id}` and versions cite ids, as §3.2 renders them. Supersession links point backwards only (`supersedes` on the newer version) and `superseded_by` is derived on read, so a committed version is never modified. There is no `current_version` pointer — the newest version that exists is the current one. `provenance/beliefs.py` is the store and decides nothing; `provenance/policy.py` is §2.2's pipeline and is the only thing that writes through it. Reasoning in [`docs/adr/ADR-016`](./docs/adr/ADR-016-the-versioned-belief-store.md).

## 7. Failure modes

The judging criteria ask directly: how does the system recover if a worker agent loops or returns a hallucination? The answers fall out of the typed-action discipline rather than being bolted on. Default posture for anything ambiguous: **fail closed** — no execution, no belief commit, escalate.

### 7.1 Hallucinated actions and looping agents

- **A hallucinated action dies at schema validation, before the gateway ever sees it.** A fabricated tool, a nonexistent target, or free-form text is rejected mechanically and returned to the Planner exactly once; a second malformed emission escalates the incident to a human.
  *"Before the gateway" and §2.1's "stage 1" describe one design.* Validation is `provenance/action.py`, a standalone pure function run first, and a rejection there reaches none of the stages that follow — no identity check, no registry read, no ABAC, no risk score. The retry budget is `action.MALFORMED_RETRY_BUDGET` (1); the control loop keeps the count, not the Planner. **As built (item 9):** that loop is `provenance/incident.py`, and the re-plan is an edge in the ADK graph from the validation node back to the Planner rather than a loop inside a prompt — the rejection reason is fed back with it, since a re-plan with no feedback is only a second roll of the dice.
- **Loops are bounded by construction.** Every incident carries a retry budget: one bounded re-plan after a `REFUTED` verification, then mandatory escalation. No agent owns its own iteration count — the control loop does, in code.
- **A plausible-but-wrong action is caught downstream.** If a hallucinated diagnosis produces an action that validates, it still faces the risk table on objective properties and verification against its pre-declared success predicate. A wrong action that executes gets `REFUTED`, and the refutation becomes a learned negative belief — the failure teaches the fleet instead of just costing it.

### 7.2 Verification honesty — the rule for learning

A memory system that learns confidently from unreliable verification is worse than one with no memory at all — it manufactures false institutional truth, then compounds it. Every proposed action declares a success predicate *before* execution. Three outcomes:

| Outcome | Action taken | What is written to memory |
|---|---|---|
| `CONFIRMED` | Incident closed | Belief committed at computed confidence |
| `REFUTED` | Bounded retry (planner re-plans with the refutation as input); second refutation → escalate, incident stays open | A **negative** belief: "rollback of v42 did *not* resolve this deviation." Confirmed negative knowledge is real knowledge |
| `INCONCLUSIVE` | Incident escalated to human | **Nothing.** No belief, no confidence, no partial credit |

**We only learn from outcomes we could actually confirm.**

*Known limitation, disclosed in [`THREAT_MODEL.md`](./THREAT_MODEL.md):* verification runs against a synthetic system whose state we control, so in the demo it cannot fail the way production fails. The `REFUTED` and `INCONCLUSIVE` paths are implemented and exercised by fault injection, not merely designed.

### 7.3 Subsystem failure posture

| Subsystem failure | Posture |
|---|---|
| Registry unreachable at authorization time | Fail closed: deny (an authorization without a live standing read violates load-bearing property 4) |
| Firestore write fails mid belief-commit | Fail closed: no partial commit; the versioned write is atomic or it didn't happen |
| Verification agent errors/timeouts | Treated as `INCONCLUSIVE`: escalate, learn nothing. **As built (item 10):** ADK re-raises a failed node out of the root workflow, so the `resolve` node never runs — the *control loop* emits the `INCONCLUSIVE` span for any action that executed without being verified, because an executed action with no verification span would read as an incident nobody checked |
| Execution fails (store unreachable, decision does not verify, no known-good version) | Fail closed: escalate with nothing verified and nothing written. An execution that did not happen must not be reported as one, so `executor.ExecutionError` is caught by the control loop and recorded as the incident's outcome rather than raised |
| Model Armor or sanitizer unavailable | Ingest halts (fail closed); incidents already in flight continue — they carry typed facts, not raw input |
| Human approver unavailable | Held actions stay parked; nothing auto-approves on timeout |

## 8. Observability and UI

A fleet of agents is invisible. Demo & Production Readiness is 30% of the score, so this is built from Phase 1, not bolted on.

**One stream:** every component emits OpenTelemetry-compliant spans (trace IDs, reasoning-chain traces) to Cloud Trace/Cloud Logging from day one. The UI, the audit log, and the counterfactual metrics all read that same stream. The trace schema is defined in Phase 1 before any agent is written. ("OpenTelemetry-compliant audit logs" is verbatim in the track brief — a literal requirement match.)

### 8.1 The span vocabulary

Five span shapes carry every authority-relevant event, one per decision the architecture makes. Four were defined in `provenance/telemetry.py` before any agent existed (ROADMAP item 2), so the six surfaces below read one contract rather than whatever each emitter happened to attach; the fifth is the incident root, which item 2 deferred because until a control loop existed there was nothing for the other four to hang from.

| Span | Emitted by | Carries |
|---|---|---|
| `provenance.incident` | the control loop (§5.3) | `incident.{id,trigger_target,trigger_signal,domain,routed_to,predicate_id,malformed_attempts,outcome}` |
| `provenance.authorization.decision` | Agent Gateway (§2.1) | `agent.{id,version,standing}`, `action.{class,target,tier,blast_radius,reversible,evidence_ids}`, the full §4.2 arithmetic as `risk.{base,criticality,blast,irreversibility,score}`, and `decision.{outcome,stage,reason,signature}` |
| `provenance.belief.commit` | Memory Policy Engine (§2.2) | `belief.{id,version,scope,domain,entity,status,confidence,threshold,supersedes}`, `evidence.{ids,source_classes,novel_count}`, and `decision.{outcome,reason,signature}` |
| `provenance.verification.outcome` | Verification Agent (§7.2) | `verification.{outcome,predicate_id,model,attempt,belief_written}` plus the action it verified |
| `provenance.reasoning.chain` | any **[LLM]** component | `agent.{id,version}`, `reasoning.{model,step,hypotheses_considered,selected_hypothesis,input_tokens,output_tokens}`, `recall.belief_ids` |

Three rules make the stream usable as an audit log rather than as debug output:

- **Identifiers, hashes, enums and numbers only — never content.** No payload text, no prompt, no model output, no rationale prose. Evidence appears as IDs and source classes; what an evidence item *said* stays out. This is what item 26's "raw inbound text never appears in the trace" is checked against.
- **The risk breakdown travels with the decision.** The gateway ledger and the approval card (§8.2, item 31) both render component-by-component arithmetic, and both read this stream — so the components are span attributes, and the emitted score must equal their sum or the emit fails.
- **Fail-closed (§7.3).** Required fields are typed; an out-of-vocabulary value raises at emit; a span that exits without recording an outcome is marked `ERROR`. An unfinished decision must not read as a clean one. `DENY`, `REJECT`, `REFUTED`, `DENIED`, `ESCALATED` and `UNROUTABLE` set `ERROR`; `INCONCLUSIVE` and `HELD` do not — ambiguity is an honest result and an incident waiting on a human is working exactly as §2.1 stage 7 designed it.

**Amended in item 7 — the authorization span's fields are optional below `agent.{id,version}`.** §2.1's earliest stages terminate before the facts the shape originally required exist: a proposal rejected at schema validation has no validated action to describe, and one rejected because Firestore was unreachable has no standing to report. Requiring them would have forced either a fifth span shape or two whole denial classes missing from the audit stream, and §2.1 stage 6 — "every outcome is ECDSA-signed into the audit log, including denials" — admits neither. So `standing` and the six `action.*` attributes may be absent; `agent.id` and `agent.version` stay required, because they come off the presented credential, which is on every path. **Absent means omitted, never emitted empty** — a span carrying `standing: ""` would read as a standing that was read and found blank. Optional widened what may be *missing*, not what may be *present*: an out-of-vocabulary value still raises. Four shapes, no new attribute key.

**Added in item 9 — `provenance.incident`, the root span.** Item 2 shipped four shapes and recorded that the root "arrives with the Orchestrator in item 9", under the condition that the module, this section and `tests/test_telemetry_schema.py` move in one commit. It is opened with only the three facts that exist at wake-on-event time (`id`, `trigger_target`, `trigger_signal`); the domain, the routed-to agent, the predicate hash and the malformed count arrive through the recorder, so a span never claims knowledge the loop did not have when it stopped. `domain`/`routed_to` are absent on an `UNROUTABLE` incident and `predicate_id` on one that produced no valid Action — the same "absent means omitted" rule the authorization span follows. `outcome` is one of `RESOLVED` / `AUTHORIZED` / `HELD` / `DENIED` / `ESCALATED` / `UNROUTABLE`.

**Added in item 10 — `RESOLVED`, and no sixth shape.** Item 10 executes, verifies and commits, and all three already had shapes waiting: `verification.outcome` and `belief.commit` were defined in item 2 with no emitter, and `resolve` is their first caller. What did change is the incident vocabulary, under item 2's standing condition (module, this section and `tests/test_telemetry_schema.py` in one commit): after item 10 an incident that stops at `AUTHORIZED` has **not** finished — it means something executed and was never verified, which is exactly the state §7.3 wants distinguishable — so a fully successful incident ends `RESOLVED`. It is not an error status. No new attribute key was added, and `belief.commit` nests *inside* `verification.outcome` because `belief_written` is not known until the commit has been attempted.

`predicate_id` is `sha256(success_predicate)[:16]` (`action.predicate_id`), and carrying it here is what makes §3.1's "declared **before** execution" checkable rather than asserted: the id is on the incident span before anything runs, and item 10's `verification.outcome` span carries the same id afterwards. The predicate's *text* never reaches a span — the redaction rule above.

The one deviation from "one stream, both destinations": Cloud **Trace** export is wired; Cloud **Logging** arrives with the first component that logs. On Cloud Run stdout reaches Cloud Logging without any exporter.

### 8.2 Six UI surfaces

- **Live fleet view** — agents, current state, which belief each is reading.
- **The belief inspector** — a belief object with its evidence, computed confidence and the arithmetic behind it, supersession chain, and decay clock. The money shot.
- **The gateway ledger** — every authorization with its risk breakdown by component, signed, including denials.
- **The approval card** — every HOLD rendered in plain language for a non-engineer: what the fleet wants to do, why, the component-by-component risk arithmetic, approve/deny. Generated from the risk table, not from a model. This is the "Unlikely Hero" surface: the approver is a store operations manager, not an engineer.
- **The counterfactual panel** — the measured A/B (memory on vs `--memory-disabled`): wall-clock, tool calls, tokens, hypotheses evaluated before the correct one.
- **The registry panel** — standing, live, so a DEGRADED transition is visible the instant it happens.

**As built (ROADMAP item 11) — two of the six, and one route.** The live fleet view and the gateway ledger are filled; the other four keep the placeholders item 3 left, each naming the item that fills it. Both read `GET /trace`, an unauthenticated read-only route serving a bounded in-process buffer of live span objects — the *same* spans `BatchSpanProcessor` exports to Cloud Trace, held by a second processor on the same provider, so §8's "the UI reads that same stream" is literal rather than approximate. Cloud Trace stays the durable record; this is the live one. Reasoning in [`docs/adr/ADR-015`](./docs/adr/ADR-015-the-trace-ui.md). **§8.1 did not change** — no new span shape, no new attribute key; every field both surfaces render was defined in item 2 or item 9.

Four things follow from that, and are worth knowing before a later item adds a surface:

- **Spans are captured at start, not at end.** "Current state" is only true if an in-flight agent is visible, and a `reasoning.chain` span stays open for the whole model call (~20s per Pro call). An SDK span's attributes are readable while it is still recording and its `end_time` is `None` until it closes, so one buffer entry serves both states and the endpoint reports `running` per span.
- **The Executor has no row, deliberately.** It emits no span (§5.8a, ADR-014); what came of it reaches the trace through the `verification.outcome` span that judges it, and that is the row the fleet view shows. A surface that inferred an executor row would be asserting state the audit stream cannot prove — the one thing §8 says these views must not do.
- **The ledger renders holds and denials, not just approvals**, which is what §2.1 stage 6 promised a surface for. A decision denied before the risk table carries no score and the panel says so rather than rendering a zero; a scored one renders `score = base + criticality + blast + irreversibility` component by component, which `set_risk()` already refuses to emit unless it sums.
- **`configure_tracing()` now always builds the provider**, and its return value means exactly "Cloud Trace export is wired" — which is what `/health`'s `tracing` field always reported. The buffer is unconditional so the UI works with no credentials, locally and in CI, which is what lets this item have an offline half at all.

## 9. Data model — the synthetic company

No real company data. A small, internally consistent fictional company built on Google's own ADK reference data: the `google/adk-samples` Customer Service sample — a fictional big-box home-improvement/gardening retailer with an existing customer/order/inventory model.

Layered on top, hand-authored for coherence:

- `inventory-api` — the subject of the SRE arc, with config versions and a known-good v41 to roll back to.
- 2–3 suppliers, with `Supplier X` / `SUP-042` pre-seeded as an AT_RISK belief so the first incident shows the system *reading* prior memory, not only writing it.
- Two additional tier-2 services that never appear in an incident — they exist so the class belief (§6.2) can demonstrably help on an entity the system has never handled before.
- A fault-injection switch on the synthetic infrastructure, so verification can genuinely return `REFUTED`.
- A named human approver: the **store operations manager**, a non-technical persona who owns the approval queue.

Recurrence matters: institutional memory only reads as real when the same entities recur. A small, coherent, recurring cast proves everything.

**As built (ROADMAP item 4).** The cast is a typed fixture in `provenance/synthetic/company.py`, written to Firestore by `scripts/seed_firestore.py`. Cymbal Home & Garden, after the `google/adk-samples` sample it derives from:

| Entity | Tier | Role |
|---|---|---|
| `inventory-api` | tier2 | The SRE arc. v42 deployed over a known-good v41 — the gap incidents #1 and #2 need |
| `pricing-api` | tier2 | Incident #3. No config history and no beliefs, so the class belief carries the diagnosis alone |
| `checkout-api` | tier2 | Never appears in an incident; enlarges the tier-2 population the class belief generalizes over |
| `SUP-042` "Verdant Supply Co." | tier1 | Supplier X — the injection and poisoning target |
| `SUP-017`, `SUP-093` | tier2 | The rest of the supply base |
| Dana Ruiz | — | Store Operations Manager; owns the item-30 approval queue |

Collections are typed rather than one polymorphic `entities` collection, config history is a `services/{id}/config_versions/{version}` subcollection, and the fault switch is a `fault_injection/{target_id}` document read at request time rather than deploy config — all three recorded in [`docs/adr/ADR-009`](./docs/adr/ADR-009-synthetic-company-collections.md).

Two values here are load-bearing elsewhere and are asserted by `tests/test_synthetic_company.py`: `inventory-api` is **tier2** and `SUP-042` is **tier1**, which is what makes §4.2's worked examples score 2 and 11. And **no entity document carries a status** — `SUP-042` becomes AT_RISK through the belief store in item 17, with evidence and a computed confidence behind it, or not at all. A seed script asserting it would be a belief with no provenance, in a place recall never looks.

## 10. Testing strategy

Verification criteria per component — these are the source of the `verify:` lines in [`ROADMAP.md`](./ROADMAP.md). Each core guarantee gets a test that tries to break it, not just one that confirms the happy path.

| Component | Core guarantee | Verify by |
|---|---|---|
| Gateway | No second path to execution; registry read at request time | Test that flips an agent's standing to DEGRADED mid-run and asserts the *next* proposal is held regardless of risk score; test that a low-risk action from a SUSPENDED agent is denied |
| Agent identity | Possession of the registered key, and only while unexpired | A credential signed by another agent's key is denied; one minted for a superseded `agent_version` is denied; one presented at its own `expires_at` is denied; an action attributed to an agent other than the credential's holder is denied |
| Risk table | Pure function of typed action | Table-driven tests over every `action_class` × tier × blast × reversibility combination; assert the two worked examples score 2 and 11 exactly |
| Schema validation | Hallucinated actions die before the gateway; the tool registry, not the Planner, is authoritative | Test a fabricated `action_class`, a nonexistent target, and free-form text: all rejected pre-gateway; a target of the wrong kind for the tool is rejected; a Planner declaring `DISABLE_COMPLIANCE_CHECKS` reversible or understating a tier fails validation; second malformed emission escalates at `MALFORMED_RETRY_BUDGET` |
| Confidence formula | Computed, never asserted; assertion-proof | Property tests: `unverified_external_claim`-only evidence yields conf 0.00; same source class restated N times yields the same conf as once; age decay is monotonic |
| Novelty check | Mechanical | Duplicate `(source_id, observed_at)` pair is not new; same source at a new timestamp is |
| Conflict rule | One sensor cannot set and clear its own alarm | Status-flip attempt with only same-source-class evidence is rejected even above the 0.70 threshold; with a different class it commits |
| Retraction | First-class, flags downstream | Retract a belief and assert every action authorized on it is flagged in the audit log |
| Standing | Earned and lost, never quietly restored | Three rejected writes in the window → DEGRADED; fourth proposal (low-risk) requires human approval; no automatic restoration path exists |
| Sweeper | Expiry is consumed | Expire a belief with no re-verification source; assert it is `UNKNOWN(stale)`, excluded from recall, never deleted |
| Recall | Index nominates, store decides | Seed a RETRACTED belief whose statement is the closest embedding match; assert it is never handed to the Orchestrator |
| Verification | Three-valued, honest | Fault-inject a failed rollback → `REFUTED` → negative belief written; force ambiguity → `INCONCLUSIVE` → nothing written |
| Bounded retry | The loop owns the count | Two consecutive `REFUTED` outcomes escalate; no third attempt occurs. For the *malformed* budget (item 9): one bad emission is re-planned with the rejection reason in the prompt, a second escalates, and the Planner is never asked a third time — asserted by counting the model's unconsumed replies |
| Control loop | One trigger, one typed proposal, and no path to the gateway but the graph | The injected `inventory-api` spike produces exactly one `provenance.authorization.decision` span, scoring 1+1+0+0=2, APPROVE; a classification outside the routing table ends the incident `UNROUTABLE` rather than defaulting to an agent |
| Injection arc | The gateway holds when filters leak | End-to-end: the §10-spec payload passes Model Armor and the sanitizer, the dangerous action is proposed, and the gateway holds it at score 11 |
| Poisoning arc | Arithmetic defense | End-to-end: unverifiable "cleared" claim → confidence unmoved → rejected → three attempts → DEGRADED on the registry panel |
| Tracing | One stream, defined shapes, no raw content | Assert each shape's span name and exact attribute set against an in-memory exporter; nested shapes share a trace ID; a risk score that doesn't equal its components and an out-of-vocabulary value both raise; no attribute key or value carries payload or model text |
| Generality | Second domain costs nothing in the control plane | Instrumented line-count report: N lines in one agent file + one registry entry; zero lines in gateway/risk table/Policy Engine/Sweeper/orchestrator |

## 11. Deployment

Cloud Run from Phase 1, not at the end: gateway, orchestrator, sweeper, and UI as services; Firestore and Vertex AI as managed dependencies. The hosted URL must work for a cold visitor — approval queue included — with credentials and step-by-step testing instructions in the README, valid through the judging period (October 1). The demo video requires an on-screen shot of the Cloud Run console and live service URLs as Google Cloud proof.
