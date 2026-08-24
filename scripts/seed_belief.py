#!/usr/bin/env python3
"""Seed the `SUP-042` AT_RISK belief, through the Policy Engine, with real arithmetic.

    GOOGLE_CLOUD_PROJECT=provenance-hackathon .venv/bin/python scripts/seed_belief.py

ARCHITECTURE.md §9 and `docs/adr/ADR-009` say it in one sentence: no entity document carries
a status, and `SUP-042` becomes AT_RISK "through the belief store in item 17, with evidence
and a computed confidence behind it, or not at all". So this writes nothing to
`suppliers/SUP-042`. It calls `policy.commit()` twice — the real §2.2 pipeline, standing read
at request time, mechanical novelty check, §4.3's computed confidence, the threshold, the
signature — and the numbers are whatever the published weights produce.

Two versions, because §3.2's belief *is* a chain and one version renders nothing:

    v1  T-8d  FLAGGED   contractual_record + agent_inference        0.575   door 0.50
    v2  T     AT_RISK   + third_party_audit                         0.770   door 0.70

v2 is a genuine §6.3 flip: it clears `FLIP_THRESHOLD` **and** rests on a source class the
chain did not already carry. It is the first time that rule runs on the demo's own belief
rather than on a scratch fixture, and it is the reason the third evidence item cannot be
another reading of one of the first two.

The eight-day gap is load-bearing, not decoration. Each version's own evidence is fresh at
its own commit, so v1 clears its door at 0.575; by the time v2 is judged those two items have
decayed and the audit has not. Back-date the pair instead and the arithmetic moves: at twelve
days v1 scores 0.4495 and is refused `BELOW_THRESHOLD`.

Create-if-absent, and **deliberately no `--reset`** — `seed_registry.py`'s posture, for a
sharper version of its reason. Items 27 and 28 attack this belief and the demo's closing shot
is that it survived; a re-run that quietly rewrote a poisoned-then-defended chain back to the
fixture would erase the only thing that shot proves. It refuses outright if the belief exists.

Needs credentials, so it is not in CI. The offline half is the SUP-042 case in
`tests/test_policy.py`; the `verify:` line is `scripts/verify_belief_inspector.py`.
"""

from __future__ import annotations

import asyncio
import os
import sys
from datetime import UTC, datetime, timedelta

from google.cloud import firestore

from provenance import beliefs, policy
from provenance.synthetic import company

ENTITY = "SUP-042"
DOMAIN = "supply-chain"
AGENT_ID = "supply-chain-agent"
BELIEF_ID = beliefs.belief_id_for(ENTITY)

# §3.2's `Authority: supply-chain-agent@v3 (standing: GOOD) + compliance-feed`, as three typed
# evidence items. The contract reference is read off the frozen fixture rather than retyped,
# so a change to the synthetic company cannot leave this citing a contract nobody holds.
V1_LAG_DAYS = 8


class Failed(Exception):
    """A check did not hold."""


def check(condition: bool, message: str) -> None:
    if not condition:
        raise Failed(message)


def an_evidence(
    source_class: str, source_id: str, at: datetime, verifiable_by: str
) -> beliefs.Evidence:
    """One typed item (§3.3). The id is content-addressed, so a re-run derives the same one."""
    stamp = at.strftime(beliefs.TIMESTAMP)
    return beliefs.Evidence(
        id=beliefs.evidence_id(source_id, stamp),
        source_id=source_id,
        source_class=source_class,  # type: ignore[arg-type]
        observed_at=stamp,
        ingested_at=stamp,
        payload_hash=beliefs.payload_hash({"entity": ENTITY, "source_id": source_id, "at": stamp}),
        verifiable_by=verifiable_by,
    )


def evidence_for(now: datetime) -> tuple[beliefs.Evidence, beliefs.Evidence, beliefs.Evidence]:
    supplier = company.supplier(ENTITY)
    first = now - timedelta(days=V1_LAG_DAYS)
    return (
        an_evidence(
            "contractual_record",
            f"contract:{supplier.contract_ref}",
            first,
            f"re-read the contract record {supplier.contract_ref}",
        ),
        an_evidence(
            "agent_inference",
            f"agent:{AGENT_ID}",
            first,
            f"re-run the delivery-variance analysis for {ENTITY}",
        ),
        an_evidence(
            "third_party_audit",
            f"compliance-feed:{ENTITY}",
            now,
            f"re-query the compliance feed for {ENTITY}",
        ),
    )


async def refuse_if_seeded(client: firestore.AsyncClient) -> None:
    """A belief already here is state some later item wrote. There is no --reset for a reason."""
    try:
        existing = await beliefs.current(BELIEF_ID, client=client)
    except beliefs.BeliefNotFound:
        return
    raise Failed(
        f"{beliefs.COLLECTION}/{BELIEF_ID} already exists at v{existing.version} "
        f"({existing.status}, conf {existing.confidence:.3f}). This script is create-if-absent "
        "and has no --reset: items 27 and 28 write to this belief, and rewriting it would "
        "erase what they proved. Delete it by hand if you genuinely want a fresh chain."
    )


async def seed(client: firestore.AsyncClient, now: datetime) -> None:
    contract, inference, audit_item = evidence_for(now)
    first_at = now - timedelta(days=V1_LAG_DAYS)

    print(f"--> v1 FLAGGED at {first_at.strftime(beliefs.TIMESTAMP)}")
    v1 = await policy.commit(
        entity=ENTITY,
        domain=DOMAIN,
        status="FLAGGED",
        evidence=[contract, inference],
        agent_id=AGENT_ID,
        now=first_at,
        client=client,
    )
    print(f"    {v1.outcome}/{v1.reason} v{v1.version} at {v1.confidence:.4f}")
    check(v1.outcome == "COMMIT", f"v1 was not committed: {v1.outcome}/{v1.reason}")
    check(abs(v1.confidence - 0.575) < 5e-4, f"v1 confidence is {v1.confidence}, expected 0.575")

    # The proposal carries only the novel item: §2.2 stage 3 resolves the accumulated set off
    # the version in force (item 13), and confidence computes over the union of the two.
    print(f"--> v2 AT_RISK at {now.strftime(beliefs.TIMESTAMP)} (+{V1_LAG_DAYS}d)")
    v2 = await policy.commit(
        entity=ENTITY,
        domain=DOMAIN,
        status="AT_RISK",
        evidence=[audit_item],
        agent_id=AGENT_ID,
        now=now,
        client=client,
    )
    print(f"    {v2.outcome}/{v2.reason} v{v2.version} at {v2.confidence:.4f}")
    check(v2.outcome == "COMMIT", f"v2 was not committed: {v2.outcome}/{v2.reason}")
    check(v2.version == 2, f"v2 landed as version {v2.version}")
    check(abs(v2.confidence - 0.7698) < 5e-4, f"v2 confidence is {v2.confidence}, expected 0.770")
    check(v2.confidence >= policy.FLIP_THRESHOLD, "v2 did not clear the flip door")


async def read_back(client: firestore.AsyncClient) -> None:
    """Every claim this script makes, re-read out of Firestore rather than trusted."""
    chain = await beliefs.history(BELIEF_ID, client=client)
    check(len(chain) == 2, f"expected two versions, found {len(chain)}")
    v1, v2 = chain

    check(v1.status == "FLAGGED", f"v1 status is {v1.status}")
    check(v1.supersedes is None, "v1 supersedes something")
    check(v1.superseded_by == 2, "v1's backlink was not derived")
    check(v1.threshold == policy.NEW_BELIEF_THRESHOLD, f"v1 faced {v1.threshold}")

    check(v2.status == "AT_RISK", f"v2 status is {v2.status}")
    check(v2.supersedes == 1, f"v2 supersedes {v2.supersedes}")
    check(v2.superseded_by is None, "v2 is not current")
    check(v2.threshold == policy.FLIP_THRESHOLD, f"v2 faced {v2.threshold}, not the flip door")
    check(v2.scope == "ENTITY", f"v2 scope is {v2.scope}")
    check(v2.domain == DOMAIN, f"v2 domain is {v2.domain}")
    # §3.2: an ENTITY belief has no statement. It is also what keeps this belief out of
    # §6.6's index, which reads root documents and skips an empty one.
    check(v2.statement == "", "an ENTITY belief acquired a statement")

    # The superseding version cites its predecessor's evidence plus the novel item (item 13).
    check(len(v2.evidence_ids) == 3, f"v2 cites {len(v2.evidence_ids)} items, expected 3")
    check(set(v1.evidence_ids) < set(v2.evidence_ids), "v2 dropped evidence v1 rested on")

    items = await beliefs.read_evidence(v2.evidence_ids, client=client)
    classes = {item.source_class for item in items}
    check(
        classes == {"contractual_record", "agent_inference", "third_party_audit"},
        f"source classes are {sorted(classes)}",
    )
    print(f"--> 2 versions, {len(items)} evidence items, {len(classes)} distinct source classes")

    # The decay clock, written at commit though item 29 is what consumes it.
    check(v2.half_life_days == policy.HALF_LIFE_DAYS[DOMAIN], f"half life is {v2.half_life_days}")
    check(v2.on_expiry == policy.ON_EXPIRY, f"on_expiry is {v2.on_expiry}")
    check(v2.expires_at > v2.committed_at, "the decay clock does not run forward")
    print(
        f"--> decay: half_life {v2.half_life_days:.0f}d, expires {v2.expires_at} ({v2.on_expiry})"
    )

    # And the arithmetic the inspector will render, recomputed here from the stored citations.
    rows = policy.contributions(
        items,
        domain=DOMAIN,
        now=datetime.strptime(v2.committed_at, beliefs.TIMESTAMP).replace(tzinfo=UTC),
    )
    for row in rows:
        print(
            f"    {row.source_class:<28} {row.base:.2f} x 2^(-{row.age_days:.1f}/30) = {row.weight:.4f}"
        )
    product = 1.0
    for row in rows:
        product *= 1 - row.weight
    # Not exact, and it cannot be: `commit()` computed the stored number at a `now` carrying
    # microseconds, while `committed_at` is TIMESTAMP-truncated to the second. One second of
    # decay against a 30-day half-life is under 1e-7, so the tolerance is what that costs --
    # anything larger than this is the formula disagreeing with itself, not the clock.
    check(
        abs((1 - product) - v2.confidence) < 1e-6,
        f"the breakdown gives {1 - product}, the version stores {v2.confidence}",
    )
    print(f"    {'1 - PROD(1 - w)':<28} {' ' * 17}= {1 - product:.4f}   threshold {v2.threshold}")


async def run(project_id: str) -> int:
    client = firestore.AsyncClient(project=project_id)
    await refuse_if_seeded(client)
    await seed(client, datetime.now(UTC))
    print("--> reading the chain back out of Firestore")
    await read_back(client)
    return 0


def main() -> int:
    project_id = os.environ.get("GOOGLE_CLOUD_PROJECT")
    if not project_id:
        print("FAIL: GOOGLE_CLOUD_PROJECT is not set.", file=sys.stderr)
        print("      Re-run with:", file=sys.stderr)
        print(
            "        GOOGLE_CLOUD_PROJECT=provenance-hackathon"
            " .venv/bin/python scripts/seed_belief.py",
            file=sys.stderr,
        )
        return 1
    print(f"==> seeding {BELIEF_ID} -> {project_id}   (by {AGENT_ID}, domain {DOMAIN})")
    try:
        code = asyncio.run(run(project_id))
    except Failed as exc:
        print(f"FAIL: {exc}", file=sys.stderr)
        return 1
    print(f"==> done. {ENTITY} is AT_RISK, and the arithmetic behind it is in the store.")
    return code


if __name__ == "__main__":
    raise SystemExit(main())
