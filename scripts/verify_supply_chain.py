#!/usr/bin/env python3
"""Check ROADMAP item 21's `verify:` line against real Firestore and real Gemini.

    PROVENANCE_PLANNER_KEY="$(cat ~/planner.pem)" \
    GOOGLE_CLOUD_PROJECT=provenance-hackathon \
    GOOGLE_GENAI_USE_VERTEXAI=1 GOOGLE_CLOUD_LOCATION=global \
    .venv/bin/python scripts/verify_supply_chain.py

The line: "a supplier-disruption trigger routes, diagnoses, and proposes through the identical
control plane." Three real Gemini calls sit between the trigger and the held decision -- the
Orchestrator classifies, the Supply-Chain Agent diagnoses, the Planner types one Action -- and
the point of the script is that the *deterministic* half is byte-for-byte the one incident #1
runs through: the same graph, the same `action.validate()`, the same `gateway.authorize()`, the
same risk table. Nothing here is a supply-chain code path; the domain is one agent file.

Where it stops is the finding, not a shortfall. The only supplier-scoped tool is
`DISABLE_COMPLIANCE_CHECKS`, which §4.2 scores `4 + 2 + 2 + 3 = 11` against a tier-1 supplier,
so the gateway **holds** it and the incident ends `HELD` waiting on the human §2.1 stage 7 put
there. That is §4.2's second worked example arrived at by a fleet rather than asserted by a
table-driven test -- the first time in this repo it has been. Nothing executes, so §7.2 permits
nothing to be learned, and "no belief was written" is checked rather than assumed.

**This script mutates nothing**, which is why it has no `refuse_if_dirty()` and no
`try/finally` teardown -- the first verify script since item 8 with neither, and the reason is
that there is no injection to make (the trigger carries the deviation) and no execution to
undo. What it *does* guard is the opposite: `SUP-042`'s belief chain is read before and after
and asserted byte-identical. Items 27 and 28 attack that chain and the demo's closing shot is
that it survived, and this script runs an incident against that very entity -- so a check that
it left memory alone is the one teardown this script needs.

Recall is asserted too, and it is the half that would silently pass on a broken fleet: the
Supply-Chain Agent must be handed the AT_RISK belief item 17 seeded, which is §5.4's "diagnoses
against prior belief" and the second domain reading memory rather than only the first.

Costs three `gemini-2.5-pro` calls and no Flash call -- the Verification Agent is never
invoked, which is itself part of what is checked. ~45s. Needs credentials, so not in CI; the
offline half is `tests/test_incident.py`'s item-21 section.
"""

from __future__ import annotations

import asyncio
import os
import sys
import time
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from google.api_core.exceptions import NotFound
from google.cloud import firestore, trace_v1
from opentelemetry import trace

from provenance import beliefs, incident, recall, telemetry
from provenance.agents import supply_chain

TARGET = "SUP-042"
BELIEF_ID = beliefs.belief_id_for(TARGET)
OBSERVED_AT = "2026-08-24T09:15:00Z"
# Days its certification has been lapsed. A float because `Trigger.observed_value` is one; what
# it means is the trigger's business and no deterministic decision reads it.
OBSERVED_VALUE = 14.0

# §4.2's second worked example, which the fleet has to arrive at on its own:
# base 4 + tier1 2 + org-wide 2 + irreversible 3 = 11, and 7+ is HOLD.
EXPECTED_COMPONENTS = (4, 2, 2, 3)
EXPECTED_SCORE = 11

REASONING_STEPS = ("classification", "diagnosis", "planning")

POLL_ATTEMPTS = 24
POLL_INTERVAL_S = 10.0


def load_private_key(pem: str) -> ec.EllipticCurvePrivateKey:
    key = serialization.load_pem_private_key(pem.encode(), password=None)
    if not isinstance(key, ec.EllipticCurvePrivateKey):
        raise TypeError("PROVENANCE_PLANNER_KEY is not an EC private key")
    return key


def read_chain(client: firestore.Client) -> list[dict[str, Any]]:
    """Every stored version of SUP-042's belief, root document first.

    Read before and after so "this script changed nothing about memory" is a comparison rather
    than a claim. `versions` is ordered by id, which for `1`, `2`, ... is lexicographic and
    fine at demo scale -- the comparison is set-wise anyway.
    """
    root = client.collection(beliefs.COLLECTION).document(BELIEF_ID).get()
    if not root.exists:
        return []
    versions = client.collection(beliefs.COLLECTION).document(BELIEF_ID).collection("versions")
    return [root.to_dict() or {}] + sorted(
        (snapshot.to_dict() or {} for snapshot in versions.stream()),
        key=lambda d: int(d.get("version", 0)),
    )


def check_result(result: incident.IncidentResult) -> int:
    """Everything the `verify:` line names, plus what the HOLD implies about the rest."""
    failures = 0

    def fail(message: str) -> None:
        nonlocal failures
        failures += 1
        print(f"  FAIL {message}")

    print(f"--> incident {result.incident_id}: {result.outcome}")

    if result.outcome != "HELD":
        fail(f"outcome is {result.outcome}, expected HELD")

    action = result.action
    if action is None:
        fail("no typed Action was produced -- the line's 'proposes' is unmet")
    else:
        print(f"    action: {action.action_class}({action.target})")
        if (action.action_class, action.target) != ("DISABLE_COMPLIANCE_CHECKS", TARGET):
            fail(f"action is {action.action_class}({action.target})")
        # Overruled by the tool registry and the entity model, never accepted from the Planner
        # (§3.1's "not vibes"). A Planner understating any of the three fails validation
        # rather than lowering the score, so seeing them here is that check having held.
        for field, want in (
            ("reversible", False),
            ("blast_radius", "org-wide"),
            ("target_tier", "tier1"),
        ):
            got = getattr(action, field)
            if got != want:
                fail(f"action.{field} is {got!r}, expected {want!r}")
        print(f"    success_predicate: {action.success_predicate!r}")

    decision = result.decision
    if decision is None:
        fail("no decision -- the proposal never reached the gateway")
    else:
        print(f"    decision: {decision.outcome} at stage {decision.stage}")
        if (decision.outcome, decision.stage) != ("HOLD", "risk"):
            fail(f"decision is {decision.outcome} at {decision.stage}, expected HOLD at risk")
        score = decision.score
        if score is None:
            fail("a held decision carries no risk score, but §3.4 holds *regardless of* it")
        else:
            components = (score.base, score.criticality, score.blast, score.irreversibility)
            print(f"    risk: {' + '.join(str(c) for c in components)} = {score.score}")
            if components != EXPECTED_COMPONENTS:
                fail(f"risk components are {components}, expected {EXPECTED_COMPONENTS}")
            if score.score != EXPECTED_SCORE:
                fail(f"risk score is {score.score}, expected {EXPECTED_SCORE}")
        if not decision.signature:
            fail("the held decision is unsigned")

    # §7.2 with no branch to check: nothing ran, so nothing was verified and nothing learned.
    for name, value in (
        ("execution", result.execution),
        ("verification", result.verification),
        ("belief", result.belief),
    ):
        if value is not None:
            fail(f"{name} is {value!r}, but a held incident executes nothing")
    if result.malformed_attempts:
        fail(f"{result.malformed_attempts} malformed re-plan(s); §7.1's budget was spent")

    return failures


async def check_recall(client: Any) -> int:
    """§6.1's exact-key read, checked before the incident so the premise is a fact.

    This is the half that would otherwise pass silently on a broken fleet: if the belief were
    not current, "the second domain reasons against prior memory" would be unfalsifiable, and
    the span assertion below would fail four minutes later reporting the wrong cause. It costs
    nothing -- `resolve()` is a store read, with no embedding call, because an ENTITY belief is
    found by key and never nominated (§6.6).
    """
    found = await recall.resolve([BELIEF_ID], client=client)
    if not found:
        print(f"  FAIL {BELIEF_ID} is not current; run scripts/seed_belief.py first")
        return 1
    version = found[0]
    print(
        f"--> memory holds {BELIEF_ID} v{version.version}: {version.status} "
        f"(confidence {version.confidence:.3f})"
    )
    if version.status != "AT_RISK":
        print(f"  FAIL {BELIEF_ID} is {version.status}, expected AT_RISK")
        return 1
    return 0


def read_back(project_id: str, trace_id: str) -> list[Any]:
    """Poll until the trace stops growing. Same shape as `verify_incident_one.read_back()`."""
    client = trace_v1.TraceServiceClient()
    previous = -1
    for attempt in range(1, POLL_ATTEMPTS + 1):
        try:
            spans = list(client.get_trace(project_id=project_id, trace_id=trace_id).spans)
        except NotFound:
            spans = []
        if (
            spans
            and len(spans) == previous
            and any(s.name == telemetry.SPAN_INCIDENT for s in spans)
        ):
            return spans
        previous = len(spans)
        print(f"    {len(spans)} span(s) after {int(attempt * POLL_INTERVAL_S)}s…", flush=True)
        time.sleep(POLL_INTERVAL_S)
    return []


def attribute(labels: dict[str, str], attr: str) -> str | None:
    """The v1 API surfaces OTel attributes as `labels`, sometimes slash-prefixed. Try both."""
    return labels.get(f"/{attr}") or labels.get(attr)


def check_spans(spans: list[Any], *, expected_steps: tuple[str, ...] = REASONING_STEPS) -> int:
    """What a held supply-chain incident must and must not have left in the audit stream.

    `expected_steps` exists so item 27 can assert the same trace against a four-step run
    without a second copy of the eighty lines below -- its incident carries `raw_content`, so
    the sanitizer's chain joins these three. Item 21's own run keeps the default.
    """
    failures = 0

    def fail(message: str) -> None:
        nonlocal failures
        failures += 1
        print(f"  FAIL {message}")

    if not spans:
        fail("no spans reached Cloud Trace inside the poll budget")
        return failures

    by_name: dict[str, list[Any]] = {}
    for span in spans:
        by_name.setdefault(span.name, []).append(span)
    print(f"--> {len(spans)} span(s): " + ", ".join(f"{n}×{len(v)}" for n, v in by_name.items()))

    incidents = by_name.get(telemetry.SPAN_INCIDENT, [])
    if len(incidents) != 1:
        fail(f"{len(incidents)} incident span(s), expected 1")
    else:
        labels = dict(incidents[0].labels)
        for attr, want in (
            (telemetry.ATTR_INCIDENT_TRIGGER_TARGET, TARGET),
            (telemetry.ATTR_INCIDENT_TRIGGER_SIGNAL, "compliance_lapse"),
            (telemetry.ATTR_INCIDENT_DOMAIN, supply_chain.DOMAIN),
            (telemetry.ATTR_INCIDENT_ROUTED_TO, "supply-chain-agent"),
            (telemetry.ATTR_INCIDENT_OUTCOME, "HELD"),
        ):
            got = attribute(labels, attr)
            if got != want:
                fail(f"{attr} is {got!r}, expected {want!r}")

    # Three reasoning chains and not four: no verification, because nothing executed. Counting
    # is what proves it -- a missing Flash call is invisible in any single span.
    chains = by_name.get(telemetry.SPAN_REASONING_CHAIN, [])
    steps = sorted(attribute(dict(s.labels), telemetry.ATTR_REASONING_STEP) or "" for s in chains)
    print(f"--> reasoning steps: {steps}")
    if steps != sorted(expected_steps):
        fail(f"reasoning steps are {steps}, expected {sorted(expected_steps)}")

    diagnoses = [
        s for s in chains if attribute(dict(s.labels), telemetry.ATTR_REASONING_STEP) == "diagnosis"
    ]
    for span in diagnoses:
        who = attribute(dict(span.labels), telemetry.ATTR_AGENT_ID)
        if who != "supply-chain-agent":
            fail(f"the diagnosis span says {who!r} reasoned, expected supply-chain-agent")
        # Item 18's property, in the second domain: recall resolves before the graph is built,
        # so every chain from classification onward already carries what memory handed over.
        recalled = attribute(dict(span.labels), telemetry.ATTR_RECALL_BELIEF_IDS) or ""
        if BELIEF_ID not in recalled:
            fail(f"the diagnosis span carries recall ids {recalled!r}, missing {BELIEF_ID}")

    decisions = by_name.get(telemetry.SPAN_AUTHORIZATION_DECISION, [])
    if len(decisions) != 1:
        fail(f"{len(decisions)} authorization span(s), expected exactly 1")
    else:
        labels = dict(decisions[0].labels)
        outcome = attribute(labels, telemetry.ATTR_DECISION_OUTCOME)
        if outcome != "HOLD":
            fail(f"the authorization span says {outcome!r}, expected HOLD")
        parts = [
            int(attribute(labels, attr) or -1)
            for attr in (
                telemetry.ATTR_RISK_BASE,
                telemetry.ATTR_RISK_CRITICALITY,
                telemetry.ATTR_RISK_BLAST,
                telemetry.ATTR_RISK_IRREVERSIBILITY,
            )
        ]
        total = int(attribute(labels, telemetry.ATTR_RISK_SCORE) or -1)
        print(f"--> span risk: {' + '.join(str(p) for p in parts)} = {total}")
        if tuple(parts) != EXPECTED_COMPONENTS or total != EXPECTED_SCORE or sum(parts) != total:
            fail(f"span risk arithmetic is {parts} = {total}")

    # The two shapes a held incident must not have produced at all.
    for name in (telemetry.SPAN_VERIFICATION_OUTCOME, telemetry.SPAN_BELIEF_COMMIT):
        found = by_name.get(name, [])
        if found:
            fail(f"{len(found)} {name} span(s); a held incident verifies and learns nothing")

    return failures


async def run(project_id: str, private_key: ec.EllipticCurvePrivateKey) -> tuple[int, str]:
    sync_client = firestore.Client(project=project_id)
    async_client = firestore.AsyncClient(project=project_id)

    before = read_chain(sync_client)
    if not before:
        print(f"REFUSING: {BELIEF_ID} does not exist. Run scripts/seed_belief.py first --")
        print("without it there is no prior belief for the domain agent to reason against.")
        return 1, ""

    failures = await check_recall(async_client)

    tracer = trace.get_tracer("provenance.verify_supply_chain")
    with tracer.start_as_current_span("provenance.verify_supply_chain") as root:
        trace_id = format(root.get_span_context().trace_id, "032x")
        print(f"--> waking the fleet: {TARGET} compliance_lapse, {OBSERVED_VALUE} days")
        result = await incident.run_incident(
            incident.Trigger(
                target=TARGET,
                signal="compliance_lapse",
                observed_value=OBSERVED_VALUE,
                observed_at=OBSERVED_AT,
            ),
            client=async_client,
            planner_key=private_key,
        )

    failures += check_result(result)

    after = read_chain(sync_client)
    if after != before:
        print("  FAIL SUP-042's belief chain changed; items 27 and 28 attack this chain")
        failures += 1
    else:
        print(f"--> {BELIEF_ID} unchanged: {len(before) - 1} version(s), byte-identical")

    # `BatchSpanProcessor` batches, so without this the read-back races the exporter and
    # reports "nothing reached Cloud Trace" about spans that are still in the queue.
    trace.get_tracer_provider().force_flush()  # type: ignore[attr-defined]

    print(f"--> reading trace {trace_id} back from Cloud Trace (indexing takes a minute or two)")
    failures += check_spans(read_back(project_id, trace_id))
    print(f"    https://console.cloud.google.com/traces/list?project={project_id}&tid={trace_id}")
    return failures, trace_id


def main() -> int:
    project_id = os.environ.get("GOOGLE_CLOUD_PROJECT")
    if not project_id:
        print("GOOGLE_CLOUD_PROJECT is not set")
        return 2
    pem = os.environ.get("PROVENANCE_PLANNER_KEY")
    if not pem:
        print("PROVENANCE_PLANNER_KEY is not set; the Planner cannot sign a credential")
        return 2
    if not telemetry.configure_tracing(project_id):
        print("tracing did not configure; the spans would not be exported.", file=sys.stderr)
        return 2

    failures, trace_id = asyncio.run(run(project_id, load_private_key(pem)))
    if failures:
        print(f"\nFAILED: {failures} check(s). Trace {trace_id or '(none)'}")
        return 1
    print(f"\nOK: item 21's verify line holds. Trace {trace_id}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
