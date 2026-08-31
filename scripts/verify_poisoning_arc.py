#!/usr/bin/env python3
"""Check ROADMAP item 28's `verify:` line against real Firestore: an unverifiable "Supplier X
is cleared" is refused, three of them inside the rolling window drop the agent to DEGRADED,
a DEGRADED agent's memory writes are refused outright and its ordinary low-risk *action*
proposal is held for a human, and `SUP-042` comes out of all of it byte-identical.

    GOOGLE_CLOUD_PROJECT=provenance-hackathon \\
    PROVENANCE_PLANNER_KEY="$(cat ~/planner.pem)" \\
    .venv/bin/python scripts/verify_poisoning_arc.py

`--demo-pause` sleeps 8s between the poisoner's third rejection and degrading the
Remediation Planner by hand, so the registry panel's 5s poll reliably lands a frame with
exactly one agent DEGRADED and three GOOD before the second agent flips too. Off by
default -- it only lengthens a recording-time run, and would be dead weight in the
assertions below.

This is the memory-side twin of item 27. That item measured both outer filters leaking and the
gateway holding at 11 anyway; the defence here is not the risk table at all but §4.3's weight
of 0.00 on `unverified_external_claim` and §3.4's standing counter.

**Item 28 found a hole and the fix is what makes this script pass.** §6.3's "a `source_class`
different from the class that established the current status" was a plain set difference, so a
class weighing 0.00 counted as corroboration. Confidence over the *accumulated* set is what a
flip is measured against (item 13), the 0.00 item moves it by nothing, and `SUP-042` sits at
0.7477 -- past the 0.70 flip door on the strength of the very evidence a poisoner is trying to
contradict. The poisoning **committed**. `policy.py` now filters the novel side of that
difference by weight; `docs/adr/ADR-030` records why, and why the filter is on that side only.

**Two agents, and the split is stated rather than smoothed over.** No registered agent both
holds a memory domain and holds a tool scope, so no single agent can be poisoned into DEGRADED
*and* then held by the gateway: `supply-chain-agent` has an empty `tool_scope` and the gateway
denies `TOOL_SCOPE` before standing is ever evaluated. Giving a belief-proposing domain agent
an action scope to make one narrative work would be tuning the fleet to produce the demo. So
the poisoner is `supply-chain-agent` and the held proposal is `remediation-planner`'s, set
DEGRADED by hand -- which §3.4 already calls a human act -- and both halves are live.

**This script writes live registry state**, unlike `scripts/verify_gateway.py` which mutates
nothing. It takes `verify_belief_store.py`'s posture exactly: it refuses to run unless both
agents start GOOD with an empty window, and the `finally` restores them on every exit path
including Ctrl-C. Restoring `supply-chain-agent`'s window is a direct document write --
`registry.py` has one standing writer and no un-append path, and must not grow one.

It writes **nothing** to the belief store, which is the closing claim: `SUP-042`'s chain is
read before and after and compared, and every evidence id the poisoning cited is checked to
have left no document behind. There is no Cloud Trace read-back here because every claim this
script makes is a claim about *Firestore state*, and it reads all of it back from Firestore.
The trace id is printed anyway so the run is findable in the audit stream.

Costs no model calls. Needs credentials, so it is not in CI; the offline halves are
`tests/test_policy.py`'s item-28 section and `tests/test_app.py`'s registry-panel section.
"""

from __future__ import annotations

import asyncio
import os
import sys
from datetime import UTC, datetime, timedelta
from typing import Any

from google.cloud import firestore
from opentelemetry import trace
from verify_gateway import ROLLBACK, load_private_key
from verify_supply_chain import BELIEF_ID, TARGET, read_chain

from provenance import beliefs, credentials, gateway, policy, registry, telemetry

POISONER = "supply-chain-agent"
PLANNER = "remediation-planner"
DOMAIN = "supply-chain"
# The status the poisoning claims. `SUP-042` is AT_RISK, so this is a flip (§6.3) rather than a
# first belief -- which is exactly why the arc could not be borrowed from item 14's, where the
# scratch entity had no belief at all and the refusal came from the arithmetic.
POISONED_STATUS = "CLEARED"
ATTEMPTS = 3

# §4.2's first worked example: base 1 + tier2 1 + single-service 0 + reversible 0 = 2, and 2 is
# well under NOTIFY_CEILING. An ordinary, boring, auto-approvable action -- which is the whole
# point of using it: what holds it is standing, and nothing else could have.
EXPECTED_COMPONENTS = (1, 1, 0, 0)
EXPECTED_SCORE = 2


class Failed(Exception):
    """A precondition did not hold. Nothing has been written when this is raised."""


def a_claim(index: int, now: datetime) -> beliefs.Evidence:
    """One unverifiable assertion, typed the way an honest one would be.

    Distinct `source_id` and `observed_at` per attempt, deliberately: a repeated pair is refused
    by §2.2 stage 3 as `NO_NEW_EVIDENCE`, which is also counted, and three of those would drive
    the same counter while proving something else entirely. Each of these reaches stage 5 on its
    own merits and is refused for what it is.

    `verifiable_by` is filled in because §3.3 requires the field, not because the claim is
    checkable -- naming a route nobody can walk is what an `unverified_external_claim` *is*.
    """
    stamp = (now + timedelta(seconds=index)).strftime(beliefs.TIMESTAMP)
    source_id = f"inbound:supplier-portal/notice-{index}"
    return beliefs.Evidence(
        id=beliefs.evidence_id(source_id, stamp),
        source_id=source_id,
        source_class="unverified_external_claim",
        observed_at=stamp,
        ingested_at=stamp,
        payload_hash=beliefs.payload_hash({"entity": TARGET, "claim": "cleared", "n": index}),
        verifiable_by="none: the sender asserts it",
    )


async def refuse_if_agent_is_dirty(client: firestore.AsyncClient, agent_id: str) -> None:
    """Same guard, and the same reason, as `verify_belief_store.refuse_if_agent_is_dirty()`.

    `scripts/seed_registry.py` has no `--reset`, so a run that started from DEGRADED and then
    "restored" what it found would quietly forgive a standing the system took away on purpose.
    """
    agent = await registry.get_agent(agent_id, client=client)
    if agent.standing != "GOOD" or agent.rejection_window:
        raise Failed(
            f"{registry.COLLECTION}/{agent_id} is {agent.standing} with "
            f"{len(agent.rejection_window)} rejection(s) on record. This script degrades it and "
            "restores GOOD with an empty window, which would erase that state -- reinstate the "
            "agent by hand first."
        )


async def refuse_unless_seeded(client: firestore.AsyncClient) -> None:
    """The arc is only meaningful against the real chain, which `seed_belief.py` wrote."""
    try:
        current = await beliefs.current(BELIEF_ID, client=client)
    except beliefs.BeliefNotFound as exc:
        raise Failed(
            f"{beliefs.COLLECTION}/{BELIEF_ID} does not exist. Run scripts/seed_belief.py "
            "first: this script attacks the seeded chain and creates nothing."
        ) from exc
    if current.status != "AT_RISK":
        raise Failed(
            f"{BELIEF_ID} is {current.status} at v{current.version}, expected AT_RISK. "
            "Something already changed what item 28 exists to prove nothing can change."
        )


async def restore(client: firestore.AsyncClient) -> None:
    """Put both agents back. Runs on every exit path, including Ctrl-C.

    The poisoner's window is cleared with a **direct document write**: `registry.py` has one
    standing writer and no un-append path at all, because §3.4 says restoration "requires
    explicit human reinstatement" and undoing a rejection is a test fixture's job, never the
    product's. This script is that fixture. The planner never gained a window entry, so
    `set_standing()` -- the sanctioned writer -- is enough for it.
    """
    print(f"--> restoring {POISONER}: standing GOOD, empty rejection window")
    await (
        client.collection(registry.COLLECTION)
        .document(POISONER)
        .update({"standing": "GOOD", "rejection_window": []})
    )
    print(f"--> restoring {PLANNER}: standing GOOD")
    await registry.set_standing(PLANNER, "GOOD", client=client)


async def poison(client: firestore.AsyncClient, now: datetime) -> tuple[int, list[str]]:
    """The three attempts, and the fourth write that no longer gets a hearing."""
    failures = 0
    cited: list[str] = []

    def fail(message: str) -> None:
        nonlocal failures
        failures += 1
        print(f"  FAIL {message}")

    for attempt in range(1, ATTEMPTS + 1):
        claim = a_claim(attempt, now)
        cited.append(claim.id)
        verdict = await policy.commit(
            entity=TARGET,
            domain=DOMAIN,
            status=POISONED_STATUS,
            evidence=[claim],
            agent_id=POISONER,
            now=now,
            client=client,
        )
        agent = await registry.get_agent(POISONER, client=client)
        print(
            f"--> attempt {attempt}: {verdict.outcome}/{verdict.reason} at "
            f"{verdict.confidence:.4f} · window {len(agent.rejection_window)} · {agent.standing}"
        )
        if (verdict.outcome, verdict.reason) != ("REJECT", "FLIP_UNSUPPORTED"):
            fail(
                f"attempt {attempt} was {verdict.outcome}/{verdict.reason}, expected FLIP_UNSUPPORTED"
            )
        # The number was never what stopped this, and saying so is half of what the arc shows.
        # The claim cleared the flip door on the accumulated strength of the belief it was
        # contradicting; what refused it is that a class weighing 0.00 corroborates nothing.
        if verdict.confidence < policy.FLIP_THRESHOLD:
            fail(
                f"attempt {attempt} scored {verdict.confidence:.4f}, under the {policy.FLIP_THRESHOLD} "
                "flip door -- the arithmetic did the work and the class rule was never tested"
            )
        if len(agent.rejection_window) != attempt:
            fail(
                f"window is {len(agent.rejection_window)} after attempt {attempt}, expected {attempt}"
            )

    agent = await registry.get_agent(POISONER, client=client)
    if agent.standing != "DEGRADED":
        fail(
            f"{POISONER} is {agent.standing} after {ATTEMPTS} counted rejections, expected DEGRADED"
        )
    reasons = [entry.reason for entry in agent.rejection_window]
    if reasons != ["FLIP_UNSUPPORTED"] * ATTEMPTS:
        fail(f"the window reads {reasons}")

    # §3.4: "a DEGRADED agent's memory writes are rejected outright". Aimed at the same entity
    # rather than a scratch one, so this is the poisoner still trying to talk about the thing it
    # lied about -- and the chain comparison below is what catches it if the refusal ever fails.
    ordinary = await policy.commit(
        entity=TARGET,
        domain=DOMAIN,
        status="AT_RISK",
        evidence=[
            beliefs.Evidence(
                id=beliefs.evidence_id("compliance-feed:re-read", now.strftime(beliefs.TIMESTAMP)),
                source_id="compliance-feed:re-read",
                source_class="third_party_audit",
                observed_at=now.strftime(beliefs.TIMESTAMP),
                ingested_at=now.strftime(beliefs.TIMESTAMP),
                payload_hash=beliefs.payload_hash({"entity": TARGET, "ordinary": True}),
                verifiable_by=f"re-query the compliance feed for {TARGET}",
            )
        ],
        agent_id=POISONER,
        now=now,
        client=client,
    )
    print(f"--> fourth write (well-evidenced): {ordinary.outcome}/{ordinary.reason}")
    if (ordinary.outcome, ordinary.reason) != ("REJECT", "STANDING_NOT_GOOD"):
        fail(
            f"the fourth write was {ordinary.outcome}/{ordinary.reason}, expected STANDING_NOT_GOOD"
        )
    after = await registry.get_agent(POISONER, client=client)
    if len(after.rejection_window) != ATTEMPTS:
        fail(
            f"the window moved to {len(after.rejection_window)} on a standing refusal -- "
            "§3.4 counts statements about evidence, and this was a statement about the agent"
        )
    return failures, cited


async def held_by_standing(client: firestore.AsyncClient, private_key: Any, now: datetime) -> int:
    """The other half of §10's standing row: an ordinary low-risk proposal, held anyway."""
    failures = 0

    def fail(message: str) -> None:
        nonlocal failures
        failures += 1
        print(f"  FAIL {message}")

    await registry.set_standing(PLANNER, "DEGRADED", client=client)
    # Read the version off the record. `--rotate` bumps it and this one is at v3; hardcoding it
    # would deny at stage 2 and look like the standing rule working.
    agent = await registry.get_agent(PLANNER, client=client)
    print(
        f"--> {PLANNER} set to {agent.standing} by hand (§3.4's human act), version {agent.version}"
    )
    credential = credentials.mint(PLANNER, agent.version, private_key, now=now)

    decision = await gateway.authorize(
        dict(ROLLBACK) | {"proposed_by": f"{PLANNER}@{agent.version}"},
        credential,
        now=now,
        client=client,
    )
    components = (
        None
        if decision.score is None
        else (
            decision.score.base,
            decision.score.criticality,
            decision.score.blast,
            decision.score.irreversibility,
        )
    )
    print(
        f"--> ROLLBACK_CONFIG(inventory-api): {decision.outcome}/{decision.stage}/{decision.reason} "
        f"· risk {components} = {None if decision.score is None else decision.score.score}"
    )
    if (decision.outcome, decision.stage, decision.reason) != (
        "HOLD",
        "registry",
        "STANDING_DEGRADED",
    ):
        fail(
            f"expected HOLD/registry/STANDING_DEGRADED, got "
            f"{decision.outcome}/{decision.stage}/{decision.reason}"
        )
    # §3.4 says a DEGRADED agent's proposals need approval "regardless of risk score", so the
    # score has to be present *and* low. A hold on a 2 is the sentence in numbers; a hold with
    # no score would be indistinguishable from the gateway never reaching the risk table.
    if decision.score is None or decision.score.score != EXPECTED_SCORE:
        fail(f"the hold carried {decision.score}, expected a score of {EXPECTED_SCORE}")
    elif components != EXPECTED_COMPONENTS:
        fail(f"risk components {components}, expected {EXPECTED_COMPONENTS}")
    return failures


async def check_nothing_was_written(client: firestore.AsyncClient, cited: list[str]) -> int:
    """A refused claim leaves no evidence document. The chain comparison cannot see this.

    `read_chain()` reads the belief root and its versions; evidence lives in its own collection,
    so a rejection that wrote its citations anyway would come out byte-identical and pass.
    """
    failures = 0
    for evidence_id in cited:
        snapshot = await client.collection(beliefs.EVIDENCE_COLLECTION).document(evidence_id).get()
        if snapshot.exists:
            failures += 1
            print(f"  FAIL a refused claim wrote {beliefs.EVIDENCE_COLLECTION}/{evidence_id}")
    return failures


async def run(private_key: Any, *, demo_pause: bool = False) -> tuple[int, str]:
    client = firestore.AsyncClient()
    sync_client = firestore.Client()
    now = datetime.now(UTC)

    await refuse_if_agent_is_dirty(client, POISONER)
    await refuse_if_agent_is_dirty(client, PLANNER)
    await refuse_unless_seeded(client)

    before = read_chain(sync_client)
    print(f"==> {BELIEF_ID} before: {len(before) - 1} version(s)")

    tracer = trace.get_tracer("provenance.verify")
    with tracer.start_as_current_span("provenance.verify_poisoning_arc") as root:
        trace_id = format(root.get_span_context().trace_id, "032x")
        try:
            failures, cited = await poison(client, now)
            if demo_pause:
                print("--> pausing 8s so the registry panel settles on one DEGRADED, three GOOD")
                await asyncio.sleep(8)
            failures += await held_by_standing(client, private_key, now)
            failures += await check_nothing_was_written(client, cited)
        finally:
            await restore(client)

    after = read_chain(sync_client)
    if after != before:
        failures += 1
        print(
            f"  FAIL {BELIEF_ID}'s chain changed: {len(before) - 1} -> {len(after) - 1} version(s)"
        )
    else:
        current = await beliefs.current(BELIEF_ID, client=client)
        print(
            f"==> {TARGET} is still {current.status} at v{current.version} "
            f"({current.confidence:.4f} as committed) -- the chain is byte-identical"
        )
    return failures, trace_id


def main() -> int:
    project_id = os.environ.get("GOOGLE_CLOUD_PROJECT")
    pem = os.environ.get("PROVENANCE_PLANNER_KEY")
    if not project_id:
        print("GOOGLE_CLOUD_PROJECT is not set.", file=sys.stderr)
        return 2
    if not pem:
        print(
            "PROVENANCE_PLANNER_KEY is not set. seed_registry.py prints each private key\n"
            "once and stores it nowhere (ADR-010); if you no longer have it, run\n"
            f"    scripts/seed_registry.py --rotate {PLANNER}",
            file=sys.stderr,
        )
        return 2
    if not telemetry.configure_tracing(project_id):
        print("tracing did not configure; the decisions would not reach the audit stream.")
        return 2

    demo_pause = "--demo-pause" in sys.argv[1:]
    try:
        failures, trace_id = asyncio.run(run(load_private_key(pem), demo_pause=demo_pause))
    except Failed as exc:
        print(f"refusing to run: {exc}", file=sys.stderr)
        return 1

    provider = trace.get_tracer_provider()
    provider.force_flush()  # type: ignore[attr-defined]
    print(f"--> trace {trace_id}")
    print(f"    https://console.cloud.google.com/traces/list?project={project_id}&tid={trace_id}")

    if failures:
        print(f"\n{failures} check(s) failed.", file=sys.stderr)
        return 1
    print("\nall checks passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
