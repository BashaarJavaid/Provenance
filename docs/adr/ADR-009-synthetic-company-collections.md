# ADR-009 — Typed collections for the synthetic company, and a fault switch that is data

**Status:** Accepted (revisit if a later domain needs entities whose kind isn't known at read time)

**Decision:** The synthetic company (`ARCHITECTURE.md` §9) is stored as typed top-level
Firestore collections — `services`, `suppliers`, `fault_injection`, `approvers`, plus the
retail base — rather than one polymorphic `entities` collection. Config history is a
subcollection, `services/{id}/config_versions/{version}`. The fault-injection switch is a
Firestore document read at request time, not deployment configuration. No entity document
carries a status.

**Reasoning, in order of weight:**

1. **A status field on an entity would be a belief without provenance (primary reason).**
   The tempting shape is `suppliers/SUP-042 { status: AT_RISK }`, because that is what the
   demo shows. But §2.2 is explicit that a status is something the Memory Policy Engine
   *commits*, with typed evidence and a computed confidence behind it and a signature over
   it. A seed script writing the same word into an entity document produces a claim with
   none of that, in a place recall would never look, that nothing can supersede or retract.
   `SUP-042` becomes AT_RISK in item 17, through the belief store, or not at all.
   `tests/test_synthetic_company.py` asserts no entity dataclass has such a field, so the
   shortcut fails the build rather than being noticed in Phase 4.
2. **The kind of an entity is always known before the read.** The argument for one
   `entities` collection is §3.1's "target must exist in the entity model" — one id, one
   lookup. But the risk table needs `target_tier` and nothing else from that lookup, and
   every caller already knows whether it holds a service or a supplier: the SRE agent's
   domain is services, the Supply-Chain agent's is suppliers, and item 6 validates a target
   against a tool schema that names which it expects. A polymorphic collection would buy
   one generic read at the cost of every document sharing a union of fields that only make
   sense for half of them — `current_config_version` on a supplier, `contract_ref` on a
   service.
3. **The fault switch has to be flippable mid-demo.** §9 wants verification to genuinely
   return `REFUTED` (item 19), which means flipping the switch between takes and,
   ideally, on camera. As deploy configuration that is a redeploy; as a Firestore document
   it is one write, visible in the same store the rest of the demo reads, and consumable by
   a request-time read exactly like registry standing (item 5). It is also honest about
   what it is: injected fault state is data about the synthetic world, not a property of
   the service that runs the fleet.

**What this deliberately does not do:** define collections for `beliefs`, `evidence` or
`agents`. Those belong to items 12 and 5, and the seed script never reads or writes them.
An entity model that pre-created empty belief documents would be prejudging a schema whose
owner doesn't exist yet.

**Revisit when:** a domain arrives whose entities are discovered rather than declared, so a
caller genuinely cannot know the collection before reading — the point at which a
polymorphic lookup starts paying for itself.

**Alternatives considered:** one `entities` collection with a `type` discriminator
(rejected above); config versions as an array field on the service document (rejected —
history is append-only and per-version, which is what a subcollection is; an array forces a
read-modify-write of the whole history to add one deploy); the fault switch as a Cloud Run
environment variable (rejected — a redeploy per flip, and invisible to the UI); seeding the
`SUP-042` AT_RISK belief here (rejected — see reason 1, and it is item 17's job).
