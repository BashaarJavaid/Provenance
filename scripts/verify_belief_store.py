#!/usr/bin/env python3
"""Check ROADMAP items 12 and 13's `verify:` lines against real Firestore: committing a
superseding belief leaves the old version intact and linked, nothing is ever deleted, and a
duplicate `(source_id, observed_at)` is refused rather than written.

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

Item 13's half is here rather than in a script of its own because §2.2 stage 3 reads the
`evidence/{id}` documents a *previous commit* wrote, and that read is the part a dict-backed
fake cannot vouch for. Note that this script hand-writes its evidence ids rather than using
`beliefs.evidence_id()` -- deliberately, because that is the case proving the novelty check
compares pairs and not ids.

Not run in CI: CI has no credentials. Costs no model calls.
"""

from __future__ import annotations

import asyncio
import os
import sys
from datetime import UTC, datetime, timedelta

from google.cloud import firestore

from provenance import beliefs, policy

ENTITY = "verify-belief-store"
BELIEF_ID = f"belief-{ENTITY}"
DOMAIN = "infrastructure"
AGENT_ID = "sre-infra-agent"
STATUS = "CONFIG_REGRESSION_PRONE"
EVIDENCE_IDS = (f"ev-{ENTITY}-1", f"ev-{ENTITY}-2", f"ev-{ENTITY}-3")
# Every observation here is a `verified_system_observation`, so §4.3's distinct-source-class
# rule collapses them to the strongest one however many accumulate: 1 - (1 - 0.60).
EXPECTED_CONFIDENCE = 0.60


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


async def propose(
    client: firestore.AsyncClient,
    evidence: list[beliefs.Evidence],
    *,
    now: datetime,
    status: str = STATUS,
) -> policy.BeliefCommit:
    return await policy.commit(
        entity=ENTITY,
        domain=DOMAIN,
        status=status,
        evidence=evidence,
        agent_id=AGENT_ID,
        now=now,
        client=client,
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
    # Three observations of the same thing an hour apart. §2.2 keys novelty on the *pair*, so
    # the clock is what makes each one new; a fresh id on the same instant would not.
    later, latest = now + timedelta(hours=1), now + timedelta(hours=2)

    print(f"==> committing v1 of {BELIEF_ID}")
    first = await propose(client, [an_evidence(EVIDENCE_IDS[0], now)], now=now)
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
    second = await propose(client, [an_evidence(EVIDENCE_IDS[1], later)], now=later)
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
    check(
        after is not None and after["evidence"] == list(EVIDENCE_IDS[:2]),
        f"v2 cites {after and after.get('evidence')!r}, expected both items (§3.2)",
    )
    print("    ok  v1 byte-identical after the write that supersedes it, and linked")
    print(f"    ok  v2 rests on {list(EVIDENCE_IDS[:2])} -- its own evidence and v1's")

    chain = await beliefs.history(BELIEF_ID, client=client)
    check(len(chain) == 2, f"history has {len(chain)} version(s), expected 2")
    check(
        [v.superseded_by for v in chain] == [2, None],
        f"derived backlinks are {[v.superseded_by for v in chain]}, expected [2, None]",
    )
    current = await beliefs.current(BELIEF_ID, client=client)
    check(current.version == 2, f"current() is v{current.version}, expected v2")
    print(f"    ok  history is {[v.version for v in chain]}, current is v{current.version}")

    for evidence_id in EVIDENCE_IDS[:2]:
        snapshot = await client.collection(beliefs.EVIDENCE_COLLECTION).document(evidence_id).get()
        check(snapshot.exists, f"{beliefs.EVIDENCE_COLLECTION}/{evidence_id} was never written")
    print(f"    ok  {beliefs.EVIDENCE_COLLECTION}/ holds both cited items (§3.3)")

    print("==> re-citing v2's evidence unchanged -- stage 3 refuses before the arithmetic")
    repeat = await propose(client, [an_evidence(EVIDENCE_IDS[1], later)], now=latest)
    print(f"    {repeat.outcome}/{repeat.reason} at {repeat.confidence:.2f}")
    check(
        (repeat.outcome, repeat.reason) == ("REJECT", "NO_NEW_EVIDENCE"),
        f"the repetition was {repeat.outcome}/{repeat.reason}, expected REJECT/NO_NEW_EVIDENCE",
    )
    check(await raw_version(client, 3) is None, "the refused repetition wrote a v3 anyway")
    print("    ok  a duplicate (source_id, observed_at) is not new (item 13's verify line)")

    print("==> proposing a status flip -- novel evidence, refused until item 14 owns the rule")
    flip = await propose(
        client, [an_evidence(EVIDENCE_IDS[2], latest)], now=latest, status="HEALTHY"
    )
    print(f"    {flip.outcome}/{flip.reason} at {flip.confidence:.2f}")
    check(
        (flip.outcome, flip.reason) == ("REJECT", "FLIP_UNSUPPORTED"),
        f"the flip was {flip.outcome}/{flip.reason}, expected REJECT/FLIP_UNSUPPORTED",
    )
    check(await raw_version(client, 3) is None, "the refused flip wrote a v3 anyway")

    print("==> committing v3 -- the same sensor, a later reading, so novel after all")
    third = await propose(client, [an_evidence(EVIDENCE_IDS[2], latest)], now=latest)
    print(f"    {third.outcome}/{third.reason} v{third.version} at {third.confidence:.2f}")
    check(third.outcome == "COMMIT", f"v3 was {third.outcome}/{third.reason}, expected COMMIT")
    stored_v3 = await raw_version(client, 3)
    check(
        stored_v3 is not None and stored_v3["evidence"] == list(EVIDENCE_IDS),
        f"v3 cites {stored_v3 and stored_v3.get('evidence')!r}, expected all three",
    )
    check(
        await raw_version(client, 1) == stored_v1,
        "v1's document changed when v3 was written",
    )
    print("    ok  same source at a new timestamp is new; v3 rests on all three")

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
