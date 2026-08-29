#!/usr/bin/env python3
"""Reset the decay clock on the demo's permanent beliefs before item 29's Sweeper expires them.

    # safe: reads only, reports every clock and exits non-zero if any is short
    GOOGLE_CLOUD_PROJECT=provenance-hackathon .venv/bin/python scripts/reaffirm_demo_beliefs.py

    # writes: one superseding version per belief, in the order the class rule requires
    GOOGLE_CLOUD_PROJECT=provenance-hackathon .venv/bin/python \\
        scripts/reaffirm_demo_beliefs.py --commit

**Why this exists.** `policy.HALF_LIFE_DAYS` is 30 in both domains, so `SUP-042`'s v2 expires
2026-09-22 and the class belief 2026-09-24 -- both *inside* the October 1 judging window. From
those dates any warm Cloud Run instance sweeps them to `UNKNOWN`, `recall.DROPPED_STATUSES`
stops handing them over, and the closing shot ("still AT_RISK — the poisoning changed nothing")
is gone along with the state items 27 and 28 both proved byte-identical.

**It is not repairable afterwards, which is why the date is hard.** Re-affirming a swept belief
is a *flip* from `UNKNOWN`, and a flip faces `FLIP_THRESHOLD` 0.70 **and** §6.3's rule that the
corroborating class must be one the chain does not already carry. Re-affirming *before* the
sweep is not a flip at all -- the status does not change -- so it faces `NEW_BELIEF_THRESHOLD`
0.50 and no class rule. Same mechanism, two very different doors, and only the date decides
which one you get.

**This is §6.5's own answer, not a workaround.** "Valid until" is a re-verification prompt; the
prompt is being answered with one fresh evidence item through `policy.commit()` -- the real
pipeline, the real registry read, the real append -- exactly as an incident would. There is no
skip list and `ADR-031` records why there must not be one, so the fix is a commit and not an
exemption. It is also why `seed_belief.py` has no `--reset` and must not grow one: this script
*supersedes*, it never rewrites. v1 and v2 are left byte-identical.

**Run `--commit` late, not early.** A commit sets `expires_at = now + 30d`, so running it in
August buys a clock that still expires before judging. The window is roughly **September 8-15**,
which lands the new expiry on October 8-15. `SAFE_UNTIL` below is the assertion that enforces
this: the script fails rather than quietly writing a version that does not survive the window.

**Order matters and is not a preference.** A CLASS belief may carry no evidence of its own
(`policy.py` raises on that); the pipeline derives its evidence set from the constituents and
measures the cap live at `now`. So on 30-day-old constituents the class commit is refused
`BELOW_THRESHOLD` and on swept ones `INSUFFICIENT_CONSTITUENTS`. The constituents are
re-affirmed first, then the class -- and the constituent list is read off the stored
`derived_from` rather than retyped, like the class name and the statement.

**Costs no model calls.** The Memory Analyst wrote the class statement once, at item 23; this
re-commits the stored sentence rather than asking for a new one, so nothing here touches Gemini
and nothing here is a new opinion about the world.

**Writes nothing that needs restoring.** A successful commit appends one `evidence/{id}` and one
`versions/{n+1}` per belief plus one OTel span. It touches neither the registry (only *counted
rejections* write standing) nor the `authorizations/` ledger (only retractions flag it). There
is no teardown -- which is the same sentence as "this is irreversible", so read the dry run
first.

Not run in CI: CI has no credentials.
"""

from __future__ import annotations

import argparse
import asyncio
import os
import sys
from datetime import UTC, date, datetime

from google.cloud import firestore

from provenance import beliefs, policy, registry

# A week of margin past October 1. The point of the whole script: a commit that does not clear
# this has bought a clock that expires during judging, which is the failure being prevented.
SAFE_UNTIL = date(2026, 10, 8)

# The one belief whose id is knowable without a read -- it is the demo's supplier and the
# subject of items 21, 27 and 28. Everything else here is discovered from the store.
SUPPLIER = "SUP-042"


class Failed(Exception):
    """A precondition did not hold, or a commit was refused."""


def check(condition: bool, message: str) -> None:
    if not condition:
        raise Failed(message)


def an_evidence(
    entity: str, source_class: str, source_id: str, verifiable_by: str, now: datetime
) -> beliefs.Evidence:
    """One typed item (§3.3), content-addressed exactly as `seed_belief.py` builds its three.

    The `source_id` deliberately matches what the chain already cites: novelty is the
    `(source_id, observed_at)` **pair** (`beliefs.novel()`), so a fresh stamp on the same feed
    is a genuine re-reading of the same source rather than a new source invented to get past a
    check. That is what "re-verify" is supposed to mean.
    """
    stamp = now.strftime(beliefs.TIMESTAMP)
    return beliefs.Evidence(
        id=beliefs.evidence_id(source_id, stamp),
        source_id=source_id,
        source_class=source_class,  # type: ignore[arg-type]
        observed_at=stamp,
        ingested_at=stamp,
        payload_hash=beliefs.payload_hash({"entity": entity, "source_id": source_id, "at": stamp}),
        verifiable_by=verifiable_by,
    )


def proposer_of(version: beliefs.BeliefVersion) -> str:
    """The agent whose authority the version rests on, read off the record.

    `committed_by` is always `memory-policy-engine` -- the Policy Engine is what commits, which
    is §1.1 property 2 and not an accident. The *proposer* is in `authority`, formatted
    `"{id}@{version} (standing: {standing})"`. Re-affirming as whoever established the chain
    keeps the authority line stable across the new version.
    """
    return version.authority.split("@")[0]


async def class_belief(client: firestore.AsyncClient) -> beliefs.BeliefVersion | None:
    """The one CLASS belief in the store, found by walking rather than by name.

    The class name is the Memory Analyst's output (item 23) and `CLAUDE.md` says to read it out
    of the store. A hardcoded `belief-service.tier2` here would be a second home for a string
    only the model is entitled to have chosen.
    """
    for belief_id in await beliefs.belief_ids(client=client):
        version = await beliefs.current(belief_id, client=client)
        if version.scope == "CLASS":
            return version
    return None


async def report(client: firestore.AsyncClient, now: datetime) -> list[beliefs.BeliefVersion]:
    """Every clock that matters, in the order `--commit` would touch them. Reads only."""
    supplier = await beliefs.current(beliefs.belief_id_for(SUPPLIER), client=client)
    generalization = await class_belief(client)
    check(generalization is not None, "no CLASS belief in the store — has item 23 been seeded?")
    assert generalization is not None  # narrowed by `check`
    constituents = [
        await beliefs.current(one, client=client) for one in generalization.derived_from
    ]

    print(f"==> the demo's permanent beliefs, as of {now.date()} (safe until {SAFE_UNTIL})")
    at_risk: list[beliefs.BeliefVersion] = []
    for version in (supplier, *constituents, generalization):
        # `policy._parse` rather than a second `strptime` here: the Sweeper's `expires_at <= now`
        # comparison is the thing being predicted, so it must be read the same way it is read.
        expires = policy._parse(version.expires_at).date()
        short = expires < SAFE_UNTIL
        at_risk += [version] if short else []
        print(
            f"    {'SHORT ' if short else 'ok    '}{version.belief_id:<28}"
            f" v{version.version} {version.status:<24} conf {version.confidence:.4f}"
            f"  expires {expires} ({(expires - now.date()).days:+}d)"
        )
        # The one state this script cannot fix. Say so here rather than letting the commit fail
        # with a threshold number that does not explain itself.
        check(
            version.status not in ("UNKNOWN", "RETRACTED"),
            f"{version.belief_id} is already {version.status} — the Sweeper reached it first."
            " Re-affirming now would be a flip, which needs 0.70 AND a source class the chain"
            " does not already carry (§6.3). Nothing in this script can undo that.",
        )
    return at_risk


async def reaffirm(
    client: firestore.AsyncClient, version: beliefs.BeliefVersion, now: datetime
) -> None:
    """One superseding version of one belief, through the pipeline every other write uses."""
    agent_id = proposer_of(version)
    agent = await registry.get_agent(agent_id)
    check(agent.standing == "GOOD", f"{agent_id} is {agent.standing}; commit would be refused")
    check(
        version.domain in agent.memory_domains,
        f"{agent_id} does not hold {version.domain}; commit would be refused",
    )

    if version.scope == "CLASS":
        # No evidence of its own: the Policy Engine derives it from the constituents, which the
        # loop above has just refreshed. The statement is the stored one -- re-committing the
        # Analyst's sentence, not asking for a new one.
        result = await policy.commit(
            entity=version.entity,
            domain=version.domain,
            status=version.status,
            evidence=[],
            agent_id=agent_id,
            now=now,
            client=client,
            scope="CLASS",
            statement=version.statement,
            derived_from=version.derived_from,
        )
    else:
        # The same status, deliberately: an unchanged status is not a flip, so this faces the
        # 0.50 door and §6.3's class rule never runs. Re-affirming with a *different* status
        # would be a different act entirely and is not what a decay clock asks for.
        result = await policy.commit(
            entity=version.entity,
            domain=version.domain,
            status=version.status,
            evidence=[evidence_for(version, now)],
            agent_id=agent_id,
            now=now,
            client=client,
        )

    print(
        f"    {result.outcome}/{result.reason} {version.belief_id}"
        f" v{result.version} at {result.confidence:.4f}"
    )
    check(result.outcome == "COMMIT", f"refused: {result.outcome}/{result.reason}")


def evidence_for(version: beliefs.BeliefVersion, now: datetime) -> beliefs.Evidence:
    """The fresh reading for one ENTITY belief, matched to what the belief is about.

    Two shapes because there are two kinds of entity in the fixture and they are re-verified by
    different means: a supplier by re-querying the compliance feed, a service by re-reading its
    document. Both cite a source the chain already carries, so this corroborates rather than
    introduces.
    """
    if version.entity == SUPPLIER:
        return an_evidence(
            version.entity,
            "third_party_audit",
            f"compliance-feed:{version.entity}",
            f"re-query the compliance feed for {version.entity}",
            now,
        )
    return an_evidence(
        version.entity,
        "verified_system_observation",
        f"firestore:services/{version.entity}",
        f"re-read services/{version.entity}",
        now,
    )


async def run(commit: bool) -> int:
    client = firestore.AsyncClient()
    now = datetime.now(UTC)
    at_risk = await report(client, now)
    if not commit:
        print(
            f"\n==> dry run. {len(at_risk)} belief(s) expire before {SAFE_UNTIL}."
            "\n    Re-run with --commit to append one superseding version to each"
            " (constituents before the class)."
        )
        return 1 if at_risk else 0

    print("\n==> committing, constituents before the class")
    supplier = await beliefs.current(beliefs.belief_id_for(SUPPLIER), client=client)
    generalization = await class_belief(client)
    assert generalization is not None  # `report()` has already checked this
    await reaffirm(client, supplier, now)
    for one in generalization.derived_from:
        await reaffirm(client, await beliefs.current(one, client=client), now)
    # Re-read: its cap is computed from the constituents *as they now are*, and they moved.
    refreshed = await class_belief(client)
    assert refreshed is not None
    await reaffirm(client, refreshed, now)

    print()
    remaining = await report(client, datetime.now(UTC))
    # No `finally` and no teardown, deliberately: an append-only store has nothing to undo, and
    # a half-finished run is a chain with fewer new versions rather than a broken one. Re-run it.
    check(
        not remaining,
        f"{len(remaining)} belief(s) still expire before {SAFE_UNTIL} — the clock did not"
        " reset. Do not assume the demo state is safe.",
    )
    print(f"\n==> done. Every clock now clears {SAFE_UNTIL}; v1 and v2 are untouched.")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--commit",
        action="store_true",
        help="append a superseding version to each belief (default: report only)",
    )
    args = parser.parse_args()

    if not os.environ.get("GOOGLE_CLOUD_PROJECT"):
        print("FAIL: GOOGLE_CLOUD_PROJECT is not set.", file=sys.stderr)
        return 1
    try:
        return asyncio.run(run(args.commit))
    except (Failed, beliefs.BeliefStoreError, registry.RegistryError) as error:
        print(f"FAIL: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
