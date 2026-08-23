#!/usr/bin/env python3
"""Check ROADMAP item 16's `verify:` line against real Firestore and a real embedding model:
a RETRACTED belief that is the closest embedding match is never handed to the Orchestrator.

    GOOGLE_CLOUD_PROJECT=provenance-hackathon GOOGLE_GENAI_USE_VERTEXAI=1 \
        .venv/bin/python scripts/verify_recall.py

Why this exists when `tests/test_recall.py` already passes: the offline half injects an
embedder, so its ranking is a fact about a hand-picked fixture. That is the right way to test
the *filter* -- a run where the retracted belief happened not to rank first would otherwise
pass while proving nothing -- but it leaves the premise untested. Here a real
`text-embedding-005` has to agree that the retracted statement is the closest match, and the
script asserts that ranking **before** it asserts the drop. Without that order the section
would pass just as well if the index were returning nothing at all.

Four beliefs are seeded through the real `beliefs.append()`, all on scratch entities that
appear in no incident, and one query separates all three behaviours:

  - an ENTITY belief, to prove §6.1's exact-key read finds it with no embedding involved;
  - a CLASS belief RETRACTED at v2, whose statement is written to be the *closest* match;
  - a CLASS belief left CURRENT, a weaker but real match, which is what proves the drop above
    is specific rather than recall simply returning nothing;
  - a CLASS belief about a different domain entirely, which must fall under the similarity
    floor -- the one number in `recall.py` that cannot be chosen offline.

Measured while building this (see `recall.SIMILARITY_FLOOR`): the three infrastructure
statements score 0.628-0.731 against this query and the supply-chain one scores 0.523, which
is the separation the floor rests on. An earlier version of this script tried to prove the
floor with an *unrelated query* instead, and that is exactly what does not work --
`text-embedding-005` scored a nonsense cafeteria query at 0.696 against the closest statement.
The floor ranks statements within one query; it does not judge whether the query was sensible.

The script writes live state and deletes all of it on every exit path including Ctrl-C, the
posture every verify script has taken since item 8. **The delete lives here and never in
`provenance/`**: §6 makes beliefs append-only and item 15 did not change that. It refuses to
run if any of its three scratch beliefs already exists, since a leftover chain would make the
ranking assertion pass for the wrong reason. It touches no registry state and costs no
reasoning-model calls -- two embedding calls, a fraction of a cent.
"""

from __future__ import annotations

import asyncio
import os
import sys

from google.cloud import firestore

from provenance import beliefs, recall

ENTITY = "verify-recall-service"
ENTITY_BELIEF = beliefs.belief_id_for(ENTITY)
CLOSEST = "belief-class-verify-recall-closest"
CURRENT = "belief-class-verify-recall-current"
DISTANT = "belief-class-verify-recall-distant"
ALL_BELIEFS = (ENTITY_BELIEF, CLOSEST, CURRENT, DISTANT)

# The incident this pretends to be woken by, phrased exactly as `recall.query_text()` would.
QUERY = recall.query_text(
    target=ENTITY,
    signal="error_rate_spike",
    tier="tier2",
    description="inventory availability and reservation API",
    observed_value=0.38,
)
# Written so the ranking is the point: the retracted one names the query's own signal and
# tier, the current one is a real but weaker infrastructure match, and the distant one is
# about another domain entirely. Measured against this query: 0.731, 0.669, 0.523.
CLOSEST_STATEMENT = (
    "error-rate spikes on tier-2 services follow configuration deploys within ten minutes"
)
CURRENT_STATEMENT = (
    "cache eviction storms on inventory services raise response times after traffic surges"
)
DISTANT_STATEMENT = (
    "supplier delivery-date slippage on contractual records precedes inventory shortfalls"
)


class Failed(Exception):
    """One assertion in this script did not hold."""


def check(condition: bool, message: str) -> None:
    if not condition:
        raise Failed(message)
    print(f"    ok: {message}")


def a_version(
    belief_id: str, version: int, *, entity: str, scope: str, status: str, statement: str = ""
) -> beliefs.BeliefVersion:
    return beliefs.BeliefVersion(
        belief_id=belief_id,
        version=version,
        scope=scope,  # type: ignore[arg-type]
        domain="infrastructure",
        entity=entity,
        status=status,
        confidence=0.60,
        threshold=0.50,
        evidence_ids=(f"ev-{belief_id}-{version}",),
        authority="verify-recall-script",
        committed_at="2026-08-22T12:00:00Z",
        committed_by="verify-recall-script",
        signature="ecdsa:scratch",
        supersedes=None if version == 1 else version - 1,
        statement=statement,
        half_life_days=30.0,
        expires_at="2026-09-21T12:00:00Z",
        on_expiry="REVERIFY",
    )


def an_evidence(belief_id: str, version: int) -> beliefs.Evidence:
    return beliefs.Evidence(
        id=f"ev-{belief_id}-{version}",
        source_id=f"scratch:{belief_id}",
        source_class="verified_system_observation",
        observed_at="2026-08-22T12:00:00Z",
        ingested_at="2026-08-22T12:00:00Z",
        payload_hash="a" * 64,
        verifiable_by="this script wrote it",
    )


async def refuse_if_dirty(client: firestore.AsyncClient) -> bool:
    """A leftover chain would make the ranking assertion pass for the wrong reason."""
    dirty = False
    for belief_id in ALL_BELIEFS:
        if (await client.collection(beliefs.COLLECTION).document(belief_id).get()).exists:
            print(f"FAIL: {beliefs.COLLECTION}/{belief_id} already exists.", file=sys.stderr)
            dirty = True
    if dirty:
        print(
            "      A previous run did not clean up. Delete those beliefs before re-running.",
            file=sys.stderr,
        )
    return dirty


async def seed(client: firestore.AsyncClient) -> None:
    print("--> seeding: one entity belief and three class beliefs (retracted, current, distant)")
    plan = [
        (ENTITY_BELIEF, 1, ENTITY, "ENTITY", "CONFIG_REGRESSION_PRONE", ""),
        (CURRENT, 1, "service.cache_pressure", "CLASS", "CORRELATED", CURRENT_STATEMENT),
        (DISTANT, 1, "supplier.delivery_slippage", "CLASS", "CORRELATED", DISTANT_STATEMENT),
        (CLOSEST, 1, "service.config_deploy", "CLASS", "CORRELATED", CLOSEST_STATEMENT),
        # §6.4's transition, appended rather than written over v1 -- which is why the root
        # document (and so the index) still carries the statement.
        (CLOSEST, 2, "service.config_deploy", "CLASS", "RETRACTED", CLOSEST_STATEMENT),
    ]
    for belief_id, version, entity, scope, status, statement in plan:
        await beliefs.append(
            a_version(
                belief_id,
                version,
                entity=entity,
                scope=scope,
                status=status,
                statement=statement,
            ),
            (an_evidence(belief_id, version),),
            client=client,
        )


async def cleanup(client: firestore.AsyncClient) -> None:
    """Remove everything this run wrote. Runs on every exit path, including Ctrl-C."""
    print("--> cleaning up: versions, evidence, root documents")
    for belief_id in ALL_BELIEFS:
        versions = client.collection(f"{beliefs.COLLECTION}/{belief_id}/versions")
        version = 1
        while (await versions.document(str(version)).get()).exists:
            await versions.document(str(version)).delete()
            await (
                client.collection(beliefs.EVIDENCE_COLLECTION)
                .document(f"ev-{belief_id}-{version}")
                .delete()
            )
            version += 1
        await client.collection(beliefs.COLLECTION).document(belief_id).delete()


async def checks(client: firestore.AsyncClient) -> None:
    print("\n[1] the index reads root documents only")
    statements = dict(await beliefs.class_statements(client=client))
    check(
        set(statements) == {CLOSEST, CURRENT, DISTANT},
        f"all three class beliefs are in the index and the entity belief is not: "
        f"{sorted(statements)}",
    )
    check(
        statements[CLOSEST] == CLOSEST_STATEMENT,
        "the retracted belief's statement survived on its root document",
    )

    print("\n[2] a real embedding model agrees the retracted one is the closest match")
    nominated = await recall.nominate(QUERY, client=client)
    check(bool(nominated), f"the index nominated something for the incident query: {nominated}")
    check(
        nominated[0] == CLOSEST,
        f"the RETRACTED belief is the closest embedding match ({nominated[0]})",
    )

    print("\n[3] and the store hands it to nobody")
    recalled = await recall.recall(ENTITY, QUERY, client=client)
    check(
        CLOSEST in recalled.nominated_ids,
        "the trace records that the retracted belief was nominated",
    )
    check(
        CLOSEST not in recalled.belief_ids,
        "the retracted belief is not among what recall handed over",
    )
    check(
        CLOSEST not in recalled.summary(),
        "and it does not reach the text a reasoning agent is shown",
    )
    check(
        [b.belief_id for b in recalled.class_beliefs] == [CURRENT],
        "the weaker but current class belief is what survived -- so the drop above is "
        "specific, not recall returning nothing",
    )

    print("\n[4] the entity belief came back by exact key, with no embedding involved")
    check(
        recalled.entity_ids == (ENTITY_BELIEF,),
        f"the exact-key read found {ENTITY_BELIEF}",
    )
    check(
        CURRENT not in recalled.entity_ids,
        "and a class belief is never among the ids an action may rest on (§6.2)",
    )
    entity_only = await recall.resolve([ENTITY_BELIEF], client=client)
    check(
        len(entity_only) == 1 and entity_only[0].statement == "",
        "the entity belief carries no statement, so it is in no index",
    )

    print("\n[5] the similarity floor holds")
    check(
        DISTANT not in nominated,
        f"the other-domain belief falls under floor {recall.SIMILARITY_FLOOR} and is never "
        f"nominated, so it can neither inform nor be dropped",
    )
    check(
        set(nominated) == {CLOSEST, CURRENT},
        f"exactly the two relevant beliefs were nominated, best first: {nominated}",
    )


async def run(project_id: str) -> int:
    client = firestore.AsyncClient(project=project_id)
    if await refuse_if_dirty(client):
        return 1
    await seed(client)
    try:
        await checks(client)
    finally:
        await cleanup(client)
    print(
        "\nPASS: the retracted belief was the closest embedding match, was nominated, and was "
        "handed to nobody; the entity belief came back by exact key; and the scratch state is "
        "gone."
    )
    return 0


def main() -> int:
    project_id = os.environ.get("GOOGLE_CLOUD_PROJECT")
    if not project_id:
        print("FAIL: GOOGLE_CLOUD_PROJECT is not set.", file=sys.stderr)
        print("      Re-run with:", file=sys.stderr)
        print(
            "        GOOGLE_CLOUD_PROJECT=provenance-hackathon GOOGLE_GENAI_USE_VERTEXAI=1"
            " .venv/bin/python scripts/verify_recall.py",
            file=sys.stderr,
        )
        return 1
    try:
        return asyncio.run(run(project_id))
    except Failed as exc:
        print(f"FAIL: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
