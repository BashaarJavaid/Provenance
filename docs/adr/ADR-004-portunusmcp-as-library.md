# ADR-004 — PortunusMCP consumed as a library dependency

**Status:** Accepted (structural containment of pre-existing code; contest-rule driven)

**Decision:** PortunusMCP — a pre-existing zero-trust MCP gateway authored by the same author — enters this repo only as a library dependency supplying identity-broker, RBAC/ABAC, and ECDSA-signing primitives. It is never vendored, forked into, or copied from. All track-facing authorization logic is new code in this repository: the deterministic risk table, reversibility/blast-radius fields on typed actions, registry standing and its request-time reads, the hold/resume human-approval path, and the approval card.

**Reasoning, in order of weight:**

1. **Contest integrity, handled structurally rather than rhetorically (primary reason).** Hackathon rules require projects be newly created during the submission period with pre-existing code disclosed. PortunusMCP touches two of the track's named pillars (Agent Identity, Agent Gateway), so the exposure is real. A dependency boundary makes the separation *mechanically visible*: the import line is the disclosure, and every scored line is new in this repo's commit history. Judges discovering vendored prior work is a submission-killing outcome; a `pyproject.toml` dependency is the same posture as depending on any auth framework.
2. **The reused part is genuinely undifferentiated.** Crypto plumbing, credential brokering, and RBAC evaluation are commodity infrastructure — the moral equivalent of an auth library. What the track scores (registry standing, risk table, typed actions, hold/resume, memory governance) doesn't exist in PortunusMCP.
3. **A real dependency stays honest.** Anything Provenance needs that Portunus doesn't expose must be written here as new code — the boundary prevents quiet scope creep of "pre-existing" into "scored."

**Consequences:** the pre-existing-code disclosure table lives in `README.md` and goes into the submission text verbatim. If a needed primitive is missing from PortunusMCP's public API, write it in this repo — do not patch it into Portunus mid-contest and re-pin.

**Revisit when:** the hackathon ends; a production successor could reconsider the split on engineering merits alone.

**Alternatives considered:** vendoring/forking the Portunus code in (indistinguishable from undisclosed pre-existing work in a repo diff — unacceptable); reimplementing identity/RBAC/signing from scratch (days of undifferentiated work taken from the memory system, the actual differentiator); skipping a real identity layer (fails the track's Agent Identity pillar outright).
