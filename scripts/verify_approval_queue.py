#!/usr/bin/env python3
"""Check ROADMAP item 30's `verify:` line against real Firestore: a held incident parks, waits
five real minutes without anything resolving it, resumes cleanly on approve — executing,
verifying and learning — and a denial is signed into the ledger with the name of whoever gave
it.

    GOOGLE_CLOUD_PROJECT=provenance-hackathon \\
    GOOGLE_GENAI_USE_VERTEXAI=1 GOOGLE_CLOUD_LOCATION=global \\
    PROVENANCE_PLANNER_KEY="$(cat ~/planner.pem)" \\
    .venv/bin/python scripts/verify_approval_queue.py

**Two modes, because the item makes two different claims.**

The default run is one process: park, wait `--park-seconds` (310 by default, which is the
item's "≥5 minutes" plus margin), assert the record is *still* `PARKED` and that nothing
resolved it, then approve and follow the incident to `RESOLVED`. That proves durability
across five minutes.

`--park-only` and `--resume <id>` are two invocations, and they are the only way ADR-007's
"survives process restarts" gets *checked* rather than asserted. The second process shares no
memory with the first — including `gateway._signing_key()`, which is generated per process
(`ADR-032` §3). It cannot verify the hold's signature and does not need to: `gateway.resolve()`
re-validates the stored proposal and recomputes §4.2, so what a second process trusts is the
risk table, not a document.

    .venv/bin/python scripts/verify_approval_queue.py --park-only
    .venv/bin/python scripts/verify_approval_queue.py --resume appr-... --verdict deny

**Which hold, and why both.** The approve half uses the DEGRADED `ROLLBACK_CONFIG` — item 28's
beat, `1 + 1 + 0 + 0 = 2`, held by *standing* rather than by score (§3.4). It is the only held
action in the fleet with an executor branch, so it is the only one where "resumes cleanly" can
mean the loop finishing. The deny half uses the supply-chain `DISABLE_COMPLIANCE_CHECKS` at
`4 + 2 + 2 + 3 = 11`, which is the beat `docs/demo-script.md` choreographs and which writes no
belief by design — nothing executed, so nothing was verified (§7.2, no branch needed).

**This script writes live registry state** and takes `verify_poisoning_arc.py`'s posture
exactly: it refuses to run unless `remediation-planner` starts GOOD with an empty window, and
the `finally` restores it on every exit path including Ctrl-C. The service fixture, the belief
chain and the ledger rows are torn down through `verify_incident_one.py`'s own teardown, which
is imported rather than duplicated — the same arrangement `verify_refuted.py` uses, so the two
scripts cannot drift over one fixture.

Costs the incident's three `gemini-2.5-pro` calls plus one `gemini-3.5-flash` verification per
resumed approval. Needs credentials, so it is not in CI; the offline halves are
`tests/test_approvals.py`, `tests/test_gateway.py`'s item-30 section, `tests/test_incident.py`'s
item-30 section and `tests/test_app.py`'s approval-queue section.
"""

from __future__ import annotations

import argparse
import asyncio
import os
import sys
import time
from datetime import UTC, datetime
from typing import Any

from google.cloud import firestore
from opentelemetry import trace
from verify_incident_one import (
    BELIEF_ID,
    TARGET,
    authorizations_for_target,
    refuse_if_dirty,
    restore,
)

from provenance import approvals, audit, beliefs, incident, registry, telemetry

PLANNER = "remediation-planner"
APPROVER = "dana.ruiz"

# §4.2's first worked example, held by standing rather than by score (§3.4).
ROLLBACK_COMPONENTS = (1, 1, 0, 0)
ROLLBACK_SCORE = 2

# §4.2's second, held by the score itself. `verify_supply_chain.py` reaches the same numbers
# through the same path without a human at the end of it.
SUPPLIER = "SUP-042"
DISABLE_COMPONENTS = (4, 2, 2, 3)
DISABLE_SCORE = 11

# The item says "≥5 minutes". 310s is that plus enough margin that a slow Firestore read on
# either side cannot turn a passing run into a 299-second one.
DEFAULT_PARK_SECONDS = 310


class Failed(Exception):
    """A precondition did not hold. Nothing has been written when this is raised."""


def fail(message: str, failures: list[str]) -> None:
    failures.append(message)
    print(f"  FAIL {message}")


# --- preconditions -----------------------------------------------------------------------------


async def refuse_if_planner_is_dirty(client: firestore.AsyncClient) -> None:
    """`verify_poisoning_arc.refuse_if_agent_is_dirty()`'s guard, and its reason.

    `scripts/seed_registry.py` has no `--reset`, so a run that started from DEGRADED and then
    "restored" GOOD would quietly forgive a standing the system took away on purpose.
    """
    agent = await registry.get_agent(PLANNER, client=client)
    if agent.standing != "GOOD" or agent.rejection_window:
        raise Failed(
            f"{registry.COLLECTION}/{PLANNER} is {agent.standing} with "
            f"{len(agent.rejection_window)} rejection(s) on record. This script degrades it and "
            "restores GOOD, which would erase that state -- reinstate the agent by hand first."
        )


def parked_records(client: firestore.Client) -> list[Any]:
    """Every queue entry, however many runs wrote them.

    Read whole rather than by id for `authorizations_for_target()`'s reason: an id is derived
    from a decision signature and the gateway's key is per process, so a run cannot reconstruct
    the id of a record the *deployed* service parked -- and that half needs cleaning up too.
    """
    return list(client.collection(approvals.COLLECTION).stream())


def refuse_if_queue_is_dirty(client: firestore.Client) -> bool:
    """Item 8's precedent, applied to the queue: refuse rather than cement.

    A pre-existing park is somebody's unanswered question. This run's teardown deletes every
    record in the collection, so answering or deleting it has to be a deliberate act.
    """
    existing = parked_records(client)
    if existing:
        states = ", ".join(sorted({(s.to_dict() or {}).get("state", "?") for s in existing}))
        print(
            f"FAIL: {approvals.COLLECTION} already holds {len(existing)} record(s) ({states}).\n"
            "      This run's teardown deletes every one of them, so somebody else's unanswered\n"
            "      hold would go with it. Answer or remove them deliberately, then re-run.",
            file=sys.stderr,
        )
        return True
    return False


def delete_approvals(client: firestore.Client) -> None:
    for snapshot in parked_records(client):
        snapshot.reference.delete()


# --- the two halves ----------------------------------------------------------------------------


async def park_the_rollback(
    client: firestore.AsyncClient, sync_client: firestore.Client, failures: list[str]
) -> str:
    """Degrade the Planner, wake the fleet, and assert the hold reached the queue."""
    print(f"--> {PLANNER} -> DEGRADED (a human act, §3.4)")
    await registry.set_standing(PLANNER, "DEGRADED", client=client)

    print(f"--> waking the fleet on {TARGET}")
    result = await incident.run_incident(
        incident.Trigger(
            target=TARGET,
            signal="error_rate",
            observed_value=0.38,
            observed_at=datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
        ),
        client=client,
    )
    print(f"    incident {result.incident_id}: {result.outcome}")
    if result.outcome != "HELD":
        fail(f"outcome is {result.outcome}, expected HELD", failures)
    decision = result.decision
    if decision is None:
        raise Failed("no decision: the proposal never reached the gateway")
    print(f"    decision: {decision.outcome} at stage {decision.stage} ({decision.reason})")
    if (decision.outcome, decision.stage, decision.reason) != (
        "HOLD",
        "registry",
        "STANDING_DEGRADED",
    ):
        fail(f"decision is {decision.outcome}/{decision.stage}/{decision.reason}", failures)
    score = decision.score
    if score is None:
        fail("a DEGRADED hold carries no score, but §3.4 holds *regardless of* it", failures)
    else:
        components = (score.base, score.criticality, score.blast, score.irreversibility)
        print(f"    risk: {' + '.join(str(c) for c in components)} = {score.score}")
        if (components, score.score) != (ROLLBACK_COMPONENTS, ROLLBACK_SCORE):
            fail(f"risk is {components} = {score.score}", failures)

    if result.approval_id is None:
        raise Failed("the hold parked nothing: there is no queue entry to resume")
    record = await approvals.get(result.approval_id, client=client)
    print(f"==> parked {record.id} at {record.parked_at} (incident {record.incident_id})")
    if record.state != "PARKED":
        fail(f"a fresh park is {record.state}, expected PARKED", failures)
    if record.incident_id != result.incident_id:
        fail(f"the park names incident {record.incident_id}, not {result.incident_id}", failures)
    if record.held_signature != decision.signature:
        fail("the park does not carry the signature the gateway signed the hold with", failures)
    if record.proposal.get("action_class") != "ROLLBACK_CONFIG":
        fail(f"the park carries {record.proposal.get('action_class')!r}", failures)
    if (record.domain, record.routed_to) != ("infrastructure", "sre-infra-agent"):
        fail(f"the park routed to {record.domain}/{record.routed_to}", failures)
    if not record.trace_id:
        fail("the park carries no trace_id, so nothing points back at the hold", failures)

    # The read side a cold judge and item 31's card both use.
    queue = await approvals.pending(client=client)
    if [r.id for r in queue] != [record.id]:
        fail(
            f"the pending queue is {[r.id for r in queue]}, expected exactly [{record.id}]",
            failures,
        )
    if authorizations_for_target(sync_client):
        fail("a held action wrote a ledger row; §6.4 records what was *authorized*", failures)
    return record.id


async def wait_and_assert_nothing_resolved(
    client: firestore.AsyncClient, approval_id: str, seconds: int, failures: list[str]
) -> None:
    """The item's "parks ≥5 minutes", and §7.3's "nothing auto-approves on timeout".

    The waiting is the assertion. Polling every thirty seconds rather than sleeping once is
    deliberate: if something *did* resolve the record, this reports when, and a run that dies
    mid-wait has still proved everything up to the last poll.
    """
    print(f"--> waiting {seconds}s with the record parked (nothing may resolve it)")
    started = time.monotonic()
    while True:
        elapsed = time.monotonic() - started
        record = await approvals.get(approval_id, client=client)
        if record.state != "PARKED":
            fail(
                f"after {elapsed:.0f}s the record is {record.state} "
                f"(approver {record.approver!r}) -- something resolved it",
                failures,
            )
            return
        if elapsed >= seconds:
            print(f"==> still PARKED after {elapsed:.0f}s, resolved_at {record.resolved_at!r}")
            return
        print(f"    {elapsed:6.0f}s  PARKED")
        await asyncio.sleep(min(30, seconds - elapsed))


async def resume_and_check(
    client: firestore.AsyncClient,
    sync_client: firestore.Client,
    approval_id: str,
    *,
    verdict: str,
    failures: list[str],
) -> None:
    """The other half of §2.1 stage 7, and everything it implies about the rest of the loop."""
    record = await approvals.get(approval_id, client=client)
    print(f"--> {APPROVER} answers {approval_id}: {verdict}")
    result = await incident.resume(approval_id, verdict=verdict, approver=APPROVER, client=client)
    print(f"    incident {result.incident_id}: {result.outcome}")
    if result.incident_id != record.incident_id:
        fail("the resumed leg reports a different incident id than the park", failures)

    decision = result.decision
    if decision is None:
        raise Failed("the resume produced no decision")
    print(f"    decision: {decision.outcome} at stage {decision.stage} ({decision.reason})")
    expected = ("APPROVE", "HUMAN_APPROVED") if verdict == "approve" else ("DENY", "HUMAN_DENIED")
    if (decision.outcome, decision.reason) != expected:
        fail(f"decision is {decision.outcome}/{decision.reason}, expected {expected}", failures)
    if decision.stage != "human":
        fail(f"decision stage is {decision.stage!r}, expected 'human'", failures)
    if decision.score is None:
        fail("the resumed decision carries no arithmetic for item 31's card to render", failures)

    # The item's own words: "denial is signed into the ledger."
    rows = [s.to_dict() or {} for s in sync_client.collection(audit.COLLECTION).stream()]
    mine = [r for r in rows if r.get("signature") == decision.signature]
    if len(mine) != 1:
        fail(f"{len(mine)} ledger row(s) carry this decision's signature, expected 1", failures)
    else:
        row = mine[0]
        print(f"    ledger {row['id']}: {row['outcome']} by {row.get('approver')!r}")
        if row.get("approver") != APPROVER:
            fail(f"the ledger row names approver {row.get('approver')!r}", failures)
        if row["outcome"] != decision.outcome:
            fail(
                f"the ledger row says {row['outcome']}, the decision says {decision.outcome}",
                failures,
            )
        if list(record.entity_ids) != list(row.get("belief_ids", [])):
            fail("the ledger row does not cite the beliefs the park carried", failures)

    after = await approvals.get(approval_id, client=client)
    print(
        f"==> {approval_id} is {after.state}, answered at {after.resolved_at} by {after.approver}"
    )
    if after.state != ("APPROVED" if verdict == "approve" else "DENIED"):
        fail(f"the record is {after.state} after a {verdict}", failures)
    if not after.resolved_at:
        fail("the record carries no resolved_at", failures)
    if after.parked_at >= after.resolved_at:
        fail(f"resolved_at {after.resolved_at} is not after parked_at {after.parked_at}", failures)

    if verdict == "approve":
        if result.outcome != "RESOLVED":
            fail(f"an approved resume ended {result.outcome}, expected RESOLVED", failures)
        if result.execution is None:
            fail("nothing executed: 'resumes cleanly' means the loop finished", failures)
        else:
            print(
                f"    executed: {result.execution.from_version} -> "
                f"{result.execution.to_version} on {result.execution.target}"
            )
        if result.verification != "CONFIRMED":
            fail(f"verification is {result.verification}, expected CONFIRMED", failures)
        if result.belief is None or result.belief.outcome != "COMMIT":
            fail("the resumed leg learned nothing; §7.2 commits on CONFIRMED", failures)
        else:
            print(
                f"    belief {result.belief.belief_id} v{result.belief.version} "
                f"at {result.belief.confidence:.4f}"
            )
            committed = await beliefs.current(BELIEF_ID, client=client)
            # The whole point of the fresh clock: a post-state measured after a five-minute
            # park did not happen at trigger time, and the stored belief must not say it did.
            if committed.created_at <= record.parked_at:
                fail(
                    f"the belief is stamped {committed.created_at}, at or before the park "
                    f"({record.parked_at}) -- the resumed leg backdated itself",
                    failures,
                )
            else:
                print(f"    committed_at {committed.created_at} > parked_at {record.parked_at}")
    else:
        if result.outcome != "DENIED":
            fail(f"a denied resume ended {result.outcome}, expected DENIED", failures)
        if (result.execution, result.verification, result.belief) != (None, None, None):
            fail("a denied action executed, verified or learned something", failures)
        else:
            print("    nothing executed, nothing verified, nothing learned -- §7.2, no branch")

    # §7.3 again, from the other side: a verdict is given once.
    try:
        await incident.resume(approval_id, verdict=verdict, approver=APPROVER, client=client)
    except approvals.ApprovalNotPending:
        print("==> a second verdict on the same record is refused")
    else:
        fail("the same record was answered twice", failures)


async def deny_the_supply_chain_hold(
    client: firestore.AsyncClient, sync_client: firestore.Client, failures: list[str]
) -> None:
    """`docs/demo-script.md`'s beat: the score-11 action parks, and the manager denies it."""
    print(f"--> waking the fleet on {SUPPLIER} (the score-{DISABLE_SCORE} hold)")
    result = await incident.run_incident(
        incident.Trigger(
            target=SUPPLIER,
            signal="compliance_lapse",
            observed_value=1.0,
            observed_at=datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
        ),
        client=client,
    )
    print(f"    incident {result.incident_id}: {result.outcome}")
    if result.outcome != "HELD" or result.approval_id is None:
        raise Failed(f"the supply-chain incident ended {result.outcome} with no park")
    decision = result.decision
    if decision is not None and decision.score is not None:
        components = (
            decision.score.base,
            decision.score.criticality,
            decision.score.blast,
            decision.score.irreversibility,
        )
        print(f"    risk: {' + '.join(str(c) for c in components)} = {decision.score.score}")
        if (components, decision.score.score) != (DISABLE_COMPONENTS, DISABLE_SCORE):
            fail(f"risk is {components} = {decision.score.score}", failures)
    await resume_and_check(
        client, sync_client, result.approval_id, verdict="deny", failures=failures
    )


# --- runners -----------------------------------------------------------------------------------


async def run_default(park_seconds: int, deny: bool) -> tuple[list[str], str]:
    client = firestore.AsyncClient()
    sync_client = firestore.Client()
    failures: list[str] = []

    await refuse_if_planner_is_dirty(client)
    if refuse_if_dirty(sync_client) or refuse_if_queue_is_dirty(sync_client):
        raise Failed("live state is already dirty; see above")

    tracer = trace.get_tracer("provenance.verify")
    with tracer.start_as_current_span("provenance.verify_approval_queue") as root:
        trace_id = format(root.get_span_context().trace_id, "032x")
        try:
            approval_id = await park_the_rollback(client, sync_client, failures)
            await wait_and_assert_nothing_resolved(client, approval_id, park_seconds, failures)
            await resume_and_check(
                client, sync_client, approval_id, verdict="approve", failures=failures
            )
            if deny:
                await deny_the_supply_chain_hold(client, sync_client, failures)
        finally:
            print(f"--> restoring {PLANNER}: standing GOOD")
            await registry.set_standing(PLANNER, "GOOD", client=client)
            print("--> restoring: v42, nominal error rate, fault off, belief deleted, queue empty")
            restore(sync_client)
            delete_approvals(sync_client)
    return failures, trace_id


async def run_park_only() -> tuple[list[str], str, str]:
    """Half a run, so the resume can happen in a process this one never touched."""
    client = firestore.AsyncClient()
    sync_client = firestore.Client()
    failures: list[str] = []

    await refuse_if_planner_is_dirty(client)
    if refuse_if_dirty(sync_client) or refuse_if_queue_is_dirty(sync_client):
        raise Failed("live state is already dirty; see above")

    tracer = trace.get_tracer("provenance.verify")
    with tracer.start_as_current_span("provenance.verify_approval_queue.park") as root:
        trace_id = format(root.get_span_context().trace_id, "032x")
        approval_id = await park_the_rollback(client, sync_client, failures)
    # Standing stays DEGRADED and the fixture stays faulted on purpose: the resume half has to
    # find the world the park left behind, which is what "survives a restart" means. Its own
    # teardown puts everything back.
    print(
        f"\n==> parked. Resume in a NEW process, and it will restore the fixture:\n"
        f"    .venv/bin/python scripts/verify_approval_queue.py --resume {approval_id}"
    )
    return failures, trace_id, approval_id


async def run_resume(approval_id: str, verdict: str) -> tuple[list[str], str]:
    """The other process. It shares nothing with the one that parked -- including the key."""
    client = firestore.AsyncClient()
    sync_client = firestore.Client()
    failures: list[str] = []

    tracer = trace.get_tracer("provenance.verify")
    with tracer.start_as_current_span("provenance.verify_approval_queue.resume") as root:
        trace_id = format(root.get_span_context().trace_id, "032x")
        try:
            await resume_and_check(
                client, sync_client, approval_id, verdict=verdict, failures=failures
            )
        finally:
            print(f"--> restoring {PLANNER}: standing GOOD")
            await registry.set_standing(PLANNER, "GOOD", client=client)
            print("--> restoring: v42, nominal error rate, fault off, belief deleted, queue empty")
            restore(sync_client)
            delete_approvals(sync_client)
    return failures, trace_id


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--park-seconds",
        type=int,
        default=DEFAULT_PARK_SECONDS,
        help=f"how long to hold the record parked before resuming (default {DEFAULT_PARK_SECONDS})",
    )
    parser.add_argument(
        "--park-only",
        action="store_true",
        help="park and stop, printing the id -- resume it from a second process",
    )
    parser.add_argument(
        "--resume", metavar="APPROVAL_ID", help="resume a park this process did not make"
    )
    parser.add_argument(
        "--verdict", choices=("approve", "deny"), default="approve", help="for --resume"
    )
    parser.add_argument(
        "--no-deny-half",
        action="store_true",
        help="skip the score-11 supply-chain denial (saves three model calls)",
    )
    args = parser.parse_args()

    project_id = os.environ.get("GOOGLE_CLOUD_PROJECT")
    if not project_id:
        print("GOOGLE_CLOUD_PROJECT is not set.", file=sys.stderr)
        return 2
    if not os.environ.get("PROVENANCE_PLANNER_KEY"):
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

    try:
        if args.park_only:
            failures, trace_id, _ = asyncio.run(run_park_only())
        elif args.resume:
            failures, trace_id = asyncio.run(run_resume(args.resume, args.verdict))
        else:
            failures, trace_id = asyncio.run(run_default(args.park_seconds, not args.no_deny_half))
    except Failed as exc:
        print(f"refusing to run: {exc}", file=sys.stderr)
        return 1

    provider = trace.get_tracer_provider()
    provider.force_flush()  # type: ignore[attr-defined]
    print(f"--> trace {trace_id}")
    print(f"    https://console.cloud.google.com/traces/list?project={project_id}&tid={trace_id}")

    if failures:
        print(f"\n{len(failures)} check(s) failed.", file=sys.stderr)
        return 1
    print("\nall checks passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
