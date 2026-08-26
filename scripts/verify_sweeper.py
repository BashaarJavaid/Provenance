#!/usr/bin/env python3
"""ROADMAP item 29's `verify:` line against real Firestore: a belief past its clock is
downgraded to `UNKNOWN(stale)`, excluded from recall, and never deleted.

    GOOGLE_CLOUD_PROJECT=provenance-hackathon GOOGLE_GENAI_USE_VERTEXAI=1 \
        .venv/bin/python scripts/verify_sweeper.py
    PROVENANCE_SERVICE_URL=https://provenance-...run.app \
        GOOGLE_CLOUD_PROJECT=provenance-hackathon GOOGLE_GENAI_USE_VERTEXAI=1 \
        .venv/bin/python scripts/verify_sweeper.py

`ARCHITECTURE.md` §10's Sweeper row is the source of every assertion here, plus the second
half of the item's own line — the downgrade visible in the belief inspector, which is read
back over HTTP from `GET /belief/{entity}` rather than described.

**The ENTITY fixture is produced by the pipeline, not written by hand.** It is committed
through `policy.commit()` with `now` forty days in the past, so its `committed_at`, its
`half_life_days` and its `expires_at` ten days ago are all things the Policy Engine computed.
A script that hand-wrote `expires_at` would be handing the thing under test the one field it
exists to read, and the test would agree with itself.

Three scratch beliefs, because §10's row is two claims and the second needs a control:

  - **`verify-sweeper-service`** — ENTITY, committed 40 days ago through the real pipeline.
    The belief the item is about. Swept, and dropped from recall's exact-key half.
  - **`service.verify_sweeper_stale`** — CLASS, past its clock, appended directly the way
    `verify_recall.py` appends its class chains (§6.2's three-constituent rule makes a real
    CLASS commit a fixture of its own). Nominated by a real `text-embedding-005` *before* the
    sweep and gone from recall after it — asserted in that order for `verify_recall.py`'s
    reason: a drop nobody can see the premise of is indistinguishable from an index returning
    nothing.
  - **`service.verify_sweeper_fresh`** — CLASS, inside its clock. The control. It must still
    be nominated and still be returned afterwards, which is what makes the two drops above
    specific rather than a sweep that expired everything or a recall that failed.

This script walks the whole store, which holds `SUP-042`'s chain and `belief-service.tier2`.
That those come back byte-identical across two sweeps is asserted by name.

Writes live state and deletes all of it on every exit path including Ctrl-C, the posture
every verify script has taken since item 8. **The deletes live here and never in
`provenance/`**: §6 makes beliefs append-only and §6.5 says a swept belief is never deleted —
this script is the only thing in the repo that removes a version, and it removes only what it
wrote. It refuses to run if any scratch belief already exists. It touches no registry state,
needs no `PROVENANCE_PLANNER_KEY`, and costs three `text-embedding-005` calls — no reasoning
model is involved, because every claim here is about the Policy Engine and a clock.
"""

from __future__ import annotations

import asyncio
import os
import sys
from datetime import UTC, datetime, timedelta

import httpx
from google.cloud import firestore

from provenance import beliefs, policy, recall, sweeper

DEFAULT_URL = "http://127.0.0.1:8000"

STALE_ENTITY = "verify-sweeper-service"
STALE = beliefs.belief_id_for(STALE_ENTITY)
STALE_CLASS_NAME = "service.verify_sweeper_stale"
STALE_CLASS = beliefs.belief_id_for(STALE_CLASS_NAME)
FRESH_CLASS_NAME = "service.verify_sweeper_fresh"
FRESH_CLASS = beliefs.belief_id_for(FRESH_CLASS_NAME)
SCRATCH = (STALE, STALE_CLASS, FRESH_CLASS)

# Permanent demo state items 27 and 28 both attacked and both left byte-identical. The Sweeper
# walks the whole store, so "it swept only what was due" has to be said about these by name.
PROTECTED = ("belief-SUP-042", "belief-service.tier2")

AGENT = "sre-infra-agent"
DOMAIN = "infrastructure"
STATUS = "CONFIG_REGRESSION_PRONE"

NOW = datetime.now(UTC)
# Forty days back against a thirty-day half-life: `expires_at` lands ten days ago, computed by
# `policy.commit()` and never written here.
LONG_AGO = NOW - timedelta(days=40)

# Both written to match the incident query below, so both are nominated and the sweep is what
# separates them. Measured against `verify_recall.py`'s floor of 0.55, these sit comfortably
# above it; if a run ever fails at step [2], that is the embedding model and not the Sweeper.
STALE_STATEMENT = (
    "error-rate spikes on tier-2 inventory services follow configuration deploys within minutes"
)
FRESH_STATEMENT = (
    "cache eviction storms on tier-2 inventory services raise response times after traffic surges"
)


class Failed(Exception):
    """One assertion in this script did not hold."""


def check(condition: bool, message: str) -> None:
    if not condition:
        raise Failed(message)
    print(f"    ok: {message}")


def an_evidence(entity: str, at: datetime) -> beliefs.Evidence:
    stamp = at.strftime(beliefs.TIMESTAMP)
    return beliefs.Evidence(
        id=beliefs.evidence_id(f"scratch:{entity}", stamp),
        source_id=f"scratch:{entity}",
        source_class="verified_system_observation",
        observed_at=stamp,
        ingested_at=stamp,
        payload_hash="a" * 64,
        verifiable_by="this script wrote it",
    )


async def refuse_if_dirty(client: firestore.AsyncClient) -> bool:
    dirty = False
    for belief_id in SCRATCH:
        if (await client.collection(beliefs.COLLECTION).document(belief_id).get()).exists:
            print(f"FAIL: {beliefs.COLLECTION}/{belief_id} already exists.", file=sys.stderr)
            dirty = True
    if dirty:
        print(
            "      A previous run did not clean up. Delete those beliefs before re-running.",
            file=sys.stderr,
        )
    return dirty


def a_class_version(
    belief_id: str, name: str, statement: str, at: datetime
) -> beliefs.BeliefVersion:
    """A CLASS chain written directly, as `verify_recall.py` writes its own (§6.2, item 23).

    A real CLASS commit derives its evidence from three current constituents, which is a
    fixture of its own; what these two have to be is *nominated and current*, and the pipeline
    claim is carried by the ENTITY belief above. `expires_at` is `at + half_life`, computed the
    same way `policy.commit()` computes it rather than picked.
    """
    stamp = at.strftime(beliefs.TIMESTAMP)
    half_life = policy.HALF_LIFE_DAYS[DOMAIN]
    return beliefs.BeliefVersion(
        belief_id=belief_id,
        version=1,
        scope="CLASS",
        domain=DOMAIN,
        entity=name,
        status="CORRELATED",
        confidence=0.60,
        threshold=0.50,
        evidence_ids=(an_evidence(name, at).id,),
        authority="verify-sweeper-script",
        committed_at=stamp,
        committed_by="verify-sweeper-script",
        signature="ecdsa:scratch",
        statement=statement,
        half_life_days=half_life,
        expires_at=(at + timedelta(days=half_life)).strftime(beliefs.TIMESTAMP),
        on_expiry=policy.ON_EXPIRY,
    )


async def seed(client: firestore.AsyncClient) -> None:
    print("--> seeding: an entity belief 40 days old, a stale class belief, a fresh one")
    stale = await policy.commit(
        entity=STALE_ENTITY,
        domain=DOMAIN,
        status=STATUS,
        evidence=[an_evidence(STALE_ENTITY, LONG_AGO)],
        agent_id=AGENT,
        now=LONG_AGO,
        client=client,
    )
    if stale.outcome != "COMMIT":
        raise Failed(f"the stale fixture did not commit: {stale.outcome}/{stale.reason}")
    for belief_id, name, statement, at in (
        (STALE_CLASS, STALE_CLASS_NAME, STALE_STATEMENT, LONG_AGO),
        (FRESH_CLASS, FRESH_CLASS_NAME, FRESH_STATEMENT, NOW),
    ):
        await beliefs.append(
            a_class_version(belief_id, name, statement, at),
            (an_evidence(name, at),),
            client=client,
        )


async def cleanup(client: firestore.AsyncClient) -> None:
    """Remove everything this run wrote, on every exit path including Ctrl-C."""
    print("--> cleaning up: versions, evidence, root documents")
    for belief_id in SCRATCH:
        versions = client.collection(f"{beliefs.COLLECTION}/{belief_id}/versions")
        version = 1
        while (snapshot := await versions.document(str(version)).get()).exists:
            for item_id in (snapshot.to_dict() or {}).get("evidence", ()):
                await client.collection(beliefs.EVIDENCE_COLLECTION).document(item_id).delete()
            await versions.document(str(version)).delete()
            version += 1
        await client.collection(beliefs.COLLECTION).document(belief_id).delete()


async def snapshot_of(client: firestore.AsyncClient, belief_id: str) -> list[dict[str, object]]:
    """Every stored version of one belief, as documents. `superseded_by` is derived, so absent."""
    return [beliefs.to_document(v) for v in await beliefs.history(belief_id, client=client)]


async def checks(client: firestore.AsyncClient, base_url: str) -> None:
    print("\n[1] the fixture is what the pipeline produced, not what this script typed")
    stale_v1 = await beliefs.current(STALE, client=client)
    check(
        stale_v1.version == 1 and stale_v1.status == STATUS,
        f"the stale belief is in force at v1 as {STATUS}",
    )
    expires = datetime.strptime(stale_v1.expires_at, beliefs.TIMESTAMP).replace(tzinfo=UTC)
    check(
        expires < NOW,
        f"its `expires_at` ({stale_v1.expires_at}) is in the past, computed from "
        f"half_life_days={stale_v1.half_life_days} by policy.commit()",
    )
    fresh_v1 = await beliefs.current(FRESH_CLASS, client=client)
    check(
        datetime.strptime(fresh_v1.expires_at, beliefs.TIMESTAMP).replace(tzinfo=UTC) > NOW,
        f"the control belief's clock has not run out ({fresh_v1.expires_at})",
    )

    print("\n[2] before the sweep, recall hands over all three")
    query = recall.query_text(
        target=STALE_ENTITY,
        signal="error_rate_spike",
        kind="service",
        tier="tier2",
        description="inventory availability and reservation API",
        observed_value=0.38,
    )
    nominated = await recall.nominate(query, client=client)
    check(
        STALE_CLASS in nominated and FRESH_CLASS in nominated,
        f"a real text-embedding-005 nominated both class beliefs: {nominated}",
    )
    before = await recall.recall(STALE_ENTITY, query, client=client)
    check(STALE in before.entity_ids, "the entity belief comes back by exact key")
    check(
        {STALE_CLASS, FRESH_CLASS} <= {b.belief_id for b in before.class_beliefs},
        "and both class beliefs survive the store's currency filter",
    )

    print("\n[3] the protected chains, before")
    protected_before = {b: await snapshot_of(client, b) for b in PROTECTED}
    for belief_id, chain in protected_before.items():
        check(bool(chain), f"{belief_id} is in the store, so comparing it after means something")

    print("\n[4] one sweep")
    swept = await sweeper.sweep(now=NOW, client=client)
    check(swept.skipped == (), f"nothing was skipped ({swept.examined} beliefs examined)")
    check(
        set(swept.expired) == {STALE, STALE_CLASS},
        f"exactly the two beliefs past their clock were expired: {swept.expired}",
    )
    check(
        FRESH_CLASS not in swept.expired,
        "and the control belief was left alone -- so this is a clock, not a purge",
    )

    print("\n[5] UNKNOWN(stale), and the predecessor untouched")
    versions = await beliefs.history(STALE, client=client)
    check(len(versions) == 2, f"the chain grew to {len(versions)} versions")
    v1, v2 = versions
    check(v2.status == policy.UNKNOWN, f"the version in force is {v2.status}")
    check(v2.supersedes == 1 and v1.superseded_by == 2, "v2 supersedes v1 and v1 says so")
    check(
        beliefs.to_document(v1) == beliefs.to_document(stale_v1),
        "v1 is byte-identical to what was committed 40 days ago -- never deleted, never edited",
    )
    check(
        v2.expires_at == v1.expires_at and v2.half_life_days == v1.half_life_days,
        f"the downgrade carries the clock that fired ({v2.expires_at}), not a fresh one",
    )
    check(
        v2.evidence_ids == v1.evidence_ids and v2.threshold == v1.threshold,
        "and carries the evidence set and the threshold forward unchanged",
    )
    evidence = await beliefs.read_evidence(v2.evidence_ids, client=client)
    recomputed = policy.confidence(evidence, domain=v2.domain, now=NOW)
    check(
        abs(v2.confidence - recomputed) < 1e-9,
        f"its confidence is §4.3 recomputed as of the sweep ({v2.confidence:.4f}), "
        f"not an asserted zero -- decayed from {v1.confidence:.4f}",
    )
    check(
        v2.authority == f"{policy.SWEEPER_ID}@{policy.SWEEPER_VERSION} (§6.5)",
        f"the version names what wrote it: {v2.authority}",
    )
    policy.verify_commit(
        policy.BeliefCommit(
            belief_id=STALE,
            version=2,
            outcome="EXPIRE",
            reason="EXPIRED",
            confidence=v2.confidence,
            signature=v2.signature,
        ),
        policy.public_key_pem(),
    )
    print("    ok: the stored signature verifies as EXPIRE/EXPIRED against this run's key")

    print("\n[6] and neither swept belief informs anything")
    after = await recall.recall(STALE_ENTITY, query, client=client)
    check(
        STALE not in after.entity_ids,
        "the swept entity belief is not among the ids an action may rest on",
    )
    check(STALE not in after.summary(), "and does not reach the text a reasoning agent is shown")
    still_nominated = await recall.nominate(query, client=client)
    check(
        STALE_CLASS in still_nominated,
        "the swept class belief is *still nominated* -- the index reads root documents and "
        "cannot see currency (ADR-005), which is what makes the drop the store's doing",
    )
    check(
        STALE_CLASS not in [b.belief_id for b in after.class_beliefs],
        "and the store hands it to nobody",
    )
    check(
        FRESH_CLASS in [b.belief_id for b in after.class_beliefs],
        "the control belief still comes back -- so the drops are specific, not recall failing",
    )

    print("\n[7] a second sweep changes nothing")
    again = await sweeper.sweep(now=NOW, client=client)
    check(again.expired == (), "neither swept belief is swept again")
    check(
        len(await beliefs.history(STALE, client=client)) == 2,
        "the chain is still 2 versions -- a warm instance cannot append forever",
    )

    print("\n[8] the protected chains, after")
    for belief_id in PROTECTED:
        check(
            await snapshot_of(client, belief_id) == protected_before[belief_id],
            f"{belief_id} is byte-identical across two sweeps",
        )

    print("\n[9] the downgrade is visible in the belief inspector")
    async with httpx.AsyncClient(timeout=30) as http:
        response = await http.get(f"{base_url}/belief/{STALE_ENTITY}")
    check(response.status_code == 200, f"GET /belief/{STALE_ENTITY} -> {response.status_code}")
    body = response.json()
    check(
        body["current"]["version"] == 2 and body["versions"][-1]["status"] == policy.UNKNOWN,
        "the inspector serves v2 as UNKNOWN",
    )
    check(
        len(body["versions"]) == 2 and body["versions"][0]["status"] == STATUS,
        "with the whole chain, including what the belief used to say",
    )
    check(
        body["versions"][-1]["expires_at"] == v1.expires_at,
        "and the expiry it renders in red is the clock that fired",
    )


async def run(project_id: str, base_url: str) -> int:
    client = firestore.AsyncClient(project=project_id)
    if await refuse_if_dirty(client):
        return 1
    await seed(client)
    try:
        await checks(client, base_url)
    finally:
        await cleanup(client)
    print(
        "\nPASS: two beliefs past their clock were downgraded to UNKNOWN with their "
        "predecessors byte-identical, dropped out of both halves of recall, were not swept "
        "twice, and rendered in the inspector; the control belief inside its clock survived; "
        "SUP-042 and belief-service.tier2 are unchanged; scratch state is gone."
    )
    return 0


def main() -> int:
    project_id = os.environ.get("GOOGLE_CLOUD_PROJECT")
    if not project_id:
        print("FAIL: GOOGLE_CLOUD_PROJECT is not set.", file=sys.stderr)
        print("      Re-run with:", file=sys.stderr)
        print(
            "        GOOGLE_CLOUD_PROJECT=provenance-hackathon GOOGLE_GENAI_USE_VERTEXAI=1"
            " .venv/bin/python scripts/verify_sweeper.py",
            file=sys.stderr,
        )
        return 1
    base_url = os.environ.get("PROVENANCE_SERVICE_URL", DEFAULT_URL).rstrip("/")
    print(f"--> inspector: {base_url}")
    try:
        return asyncio.run(run(project_id, base_url))
    except Failed as exc:
        print(f"FAIL: {exc}", file=sys.stderr)
        return 1
    except httpx.HTTPError as exc:
        print(f"FAIL: could not reach {base_url} ({exc}).", file=sys.stderr)
        print("      Start it with `.venv/bin/uvicorn provenance.app:app`, or set", file=sys.stderr)
        print("      PROVENANCE_SERVICE_URL to the deployed service.", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
