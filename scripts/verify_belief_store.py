#!/usr/bin/env python3
"""Check ROADMAP item 12's `verify:` line against real Firestore: committing a superseding
belief leaves the old version intact and linked, and nothing is ever deleted.

    GOOGLE_CLOUD_PROJECT=provenance-hackathon .venv/bin/python scripts/verify_belief_store.py

Why this exists when `tests/test_beliefs.py` already passes: the guarantee is a *Firestore*
one. "The old version survives" rests on `create()` refusing to overwrite a document that
exists, and a fake asserting that asserts our belief about Firestore rather than Firestore
itself. Everything here runs through `policy.commit()` -- the real pipeline, the real store,
the real registry read -- against a scratch entity that appears in no incident.

The script writes live state and cleans up after itself on every exit path including Ctrl-C,
the same posture as `scripts/verify_denial_by_registry.py`. **The delete lives here and never
in `provenance/`**: §6 makes beliefs append-only, and the only two things that may remove one
are a test fixture and a retraction (§6.4, item 15) -- and only one of those belongs in the
product. It refuses to run if the scratch belief already exists, since a leftover chain would
make "v2 supersedes v1" pass for the wrong reason.

Not run in CI: CI has no credentials. Costs no model calls.
"""

from __future__ import annotations

import asyncio
import os
import sys
from datetime import UTC, datetime

from google.cloud import firestore

from provenance import beliefs, policy

ENTITY = "verify-belief-store"
BELIEF_ID = f"belief-{ENTITY}"
DOMAIN = "infrastructure"
AGENT_ID = "sre-infra-agent"
STATUS = "CONFIG_REGRESSION_PRONE"
EVIDENCE_IDS = (f"ev-{ENTITY}-1", f"ev-{ENTITY}-2")
EXPECTED_CONFIDENCE = 0.60  # one fresh verified_system_observation: 1 - (1 - 0.60)


class Failed(Exception):
    """A check did not hold. Raised so the cleanup in `finally` still runs."""


def check(condition: bool, message: str) -> None:
    if not condition:
        raise Failed(message)


def an_evidence(evidence_id: str, now: datetime) -> beliefs.Evidence:
    stamp = now.strftime(beliefs.TIMESTAMP)
    return beliefs.Evidence(
        id=evidence_id,
        source_id=f"firestore:services/{ENTITY}",
        source_class="verified_system_observation",
        observed_at=stamp,
        ingested_at=stamp,
        payload_hash=beliefs.payload_hash({"entity": ENTITY, "evidence": evidence_id}),
        verifiable_by=f"re-read services/{ENTITY}",
    )


async def refuse_if_dirty(client: firestore.AsyncClient) -> None:
    try:
        existing = await beliefs.current(BELIEF_ID, client=client)
    except beliefs.BeliefNotFound:
        return
    raise Failed(
        f"{beliefs.COLLECTION}/{BELIEF_ID} already exists at v{existing.version}. "
        "A previous run did not clean up; remove it before re-running."
    )


async def raw_version(client: firestore.AsyncClient, version: int) -> dict[str, object] | None:
    snapshot = (
        await client.collection(f"{beliefs.COLLECTION}/{BELIEF_ID}/versions")
        .document(str(version))
        .get()
    )
    return snapshot.to_dict() if snapshot.exists else None


async def cleanup(client: firestore.AsyncClient) -> None:
    """Remove everything this run wrote. Runs on every exit path, including Ctrl-C."""
    print("--> cleaning up: versions, evidence, root document")
    version = 1
    while await raw_version(client, version) is not None:
        await (
            client.collection(f"{beliefs.COLLECTION}/{BELIEF_ID}/versions")
            .document(str(version))
            .delete()
        )
        version += 1
    for evidence_id in EVIDENCE_IDS:
        await client.collection(beliefs.EVIDENCE_COLLECTION).document(evidence_id).delete()
    await client.collection(beliefs.COLLECTION).document(BELIEF_ID).delete()


async def checks(client: firestore.AsyncClient) -> None:
    now = datetime.now(UTC).replace(microsecond=0)

    print(f"==> committing v1 of {BELIEF_ID}")
    first = await policy.commit(
        entity=ENTITY,
        domain=DOMAIN,
        status=STATUS,
        evidence=[an_evidence(EVIDENCE_IDS[0], now)],
        agent_id=AGENT_ID,
        now=now,
        client=client,
    )
    print(f"    {first.outcome}/{first.reason} v{first.version} at {first.confidence:.2f}")
    check(first.outcome == "COMMIT", f"v1 was {first.outcome}/{first.reason}, expected COMMIT")
    check(first.version == 1, f"first commit landed at v{first.version}, expected v1")
    check(
        abs(first.confidence - EXPECTED_CONFIDENCE) < 1e-6,
        f"v1 confidence is {first.confidence}, expected {EXPECTED_CONFIDENCE}",
    )
    stored_v1 = await raw_version(client, 1)
    check(stored_v1 is not None, "v1 committed but no version document was written")

    print("==> committing v2 -- same status, new evidence (a re-affirmation, not a flip)")
    second = await policy.commit(
        entity=ENTITY,
        domain=DOMAIN,
        status=STATUS,
        evidence=[an_evidence(EVIDENCE_IDS[1], now)],
        agent_id=AGENT_ID,
        now=now,
        client=client,
    )
    print(f"    {second.outcome}/{second.reason} v{second.version} at {second.confidence:.2f}")
    check(second.outcome == "COMMIT", f"v2 was {second.outcome}/{second.reason}, expected COMMIT")
    check(second.version == 2, f"second commit landed at v{second.version}, expected v2")

    # The verify line, both halves, read back out of Firestore rather than inferred.
    after = await raw_version(client, 2)
    check(after is not None, "v2 committed but no version document was written")
    check(
        await raw_version(client, 1) == stored_v1,
        "v1's document changed when v2 was written -- the store is not append-only",
    )
    check(
        after is not None and after["supersedes"] == 1,
        f"v2 carries supersedes={after and after.get('supersedes')!r}, expected 1",
    )
    check(
        stored_v1 is not None and "superseded_by" not in stored_v1,
        "v1 carries a stored superseded_by; the backlink is meant to be derived on read",
    )
    print("    ok  v1 byte-identical after the write that supersedes it, and linked")

    chain = await beliefs.history(BELIEF_ID, client=client)
    check(len(chain) == 2, f"history has {len(chain)} version(s), expected 2")
    check(
        [v.superseded_by for v in chain] == [2, None],
        f"derived backlinks are {[v.superseded_by for v in chain]}, expected [2, None]",
    )
    current = await beliefs.current(BELIEF_ID, client=client)
    check(current.version == 2, f"current() is v{current.version}, expected v2")
    print(f"    ok  history is {[v.version for v in chain]}, current is v{current.version}")

    for evidence_id in EVIDENCE_IDS:
        snapshot = await client.collection(beliefs.EVIDENCE_COLLECTION).document(evidence_id).get()
        check(snapshot.exists, f"{beliefs.EVIDENCE_COLLECTION}/{evidence_id} was never written")
    print(f"    ok  {beliefs.EVIDENCE_COLLECTION}/ holds both cited items (§3.3)")

    print("==> proposing a status flip -- refused until item 14 owns the rule")
    flip = await policy.commit(
        entity=ENTITY,
        domain=DOMAIN,
        status="HEALTHY",
        evidence=[an_evidence(EVIDENCE_IDS[1], now)],
        agent_id=AGENT_ID,
        now=now,
        client=client,
    )
    print(f"    {flip.outcome}/{flip.reason} at {flip.confidence:.2f}")
    check(
        (flip.outcome, flip.reason) == ("REJECT", "FLIP_UNSUPPORTED"),
        f"the flip was {flip.outcome}/{flip.reason}, expected REJECT/FLIP_UNSUPPORTED",
    )
    check(await raw_version(client, 3) is None, "the refused flip wrote a v3 anyway")

    print("==> re-writing v1 directly -- must be refused by the store, not by us")
    try:
        await beliefs.append(chain[0], [], client=client)
    except beliefs.VersionConflict:
        print("    ok  VersionConflict; create() will not overwrite a committed version")
    else:
        raise Failed("re-appending v1 succeeded -- the store is overwriting versions")

    check(
        await raw_version(client, 1) == stored_v1,
        "v1 changed during the refusal checks",
    )


async def run(project_id: str) -> int:
    client = firestore.AsyncClient(project=project_id)
    await refuse_if_dirty(client)
    try:
        await checks(client)
    except Failed as exc:
        print(f"FAIL: {exc}", file=sys.stderr)
        return 1
    finally:
        await cleanup(client)
    print(f"==> done. {BELIEF_ID} superseded cleanly and the scratch state is gone.")
    return 0


def main() -> int:
    project_id = os.environ.get("GOOGLE_CLOUD_PROJECT")
    if not project_id:
        print("FAIL: GOOGLE_CLOUD_PROJECT is not set.", file=sys.stderr)
        print("      Re-run with:", file=sys.stderr)
        print(
            "        GOOGLE_CLOUD_PROJECT=provenance-hackathon"
            " .venv/bin/python scripts/verify_belief_store.py",
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
