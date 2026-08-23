#!/usr/bin/env python3
"""Check ROADMAP items 12, 13 and 14's `verify:` lines against real Firestore: committing a
superseding belief leaves the old version intact and linked, nothing is ever deleted, a
duplicate `(source_id, observed_at)` is refused rather than written, a status flip is refused
on same-class evidence even above 0.70 and commits on a different class, and three refused
writes degrade the agent that made them.

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

Item 14 adds two sections, in this order because the second one takes the agent's authority
away and the first one needs it:

  - **The conflict rule.** The chain reaches two source classes, then a flip is proposed on a
    third reading of a class already in the set -- above 0.70, so the number is not what stops
    it -- and then on a class that is genuinely new. §6.3 as arithmetic, against a real store.
  - **The standing counter.** Three unverifiable claims about a *second* scratch entity, each
    refused at 0.00, driving `sre-infra-agent` to DEGRADED. This half writes **live registry
    state**, so it takes `scripts/verify_denial_by_registry.py`'s posture exactly: it refuses
    to run unless the record starts GOOD with an empty window, and the `finally` restores both
    fields on any exit path including Ctrl-C. Restoring the window is a direct document write
    -- `registry.py` has no un-append path and must not grow one.

Not run in CI: CI has no credentials. Costs no model calls.
"""

from __future__ import annotations

import asyncio
import os
import sys
from datetime import UTC, datetime, timedelta

from google.cloud import firestore

from provenance import beliefs, policy, registry

ENTITY = "verify-belief-store"
BELIEF_ID = f"belief-{ENTITY}"
DOMAIN = "infrastructure"
AGENT_ID = "sre-infra-agent"
STATUS = "CONFIG_REGRESSION_PRONE"
EVIDENCE_IDS = (f"ev-{ENTITY}-1", f"ev-{ENTITY}-2", f"ev-{ENTITY}-3")
# Every observation in items 12-13's half is a `verified_system_observation`, so §4.3's
# distinct-source-class rule collapses them to the strongest one however many accumulate:
# 1 - (1 - 0.60).
EXPECTED_CONFIDENCE = 0.60

# Item 14's half. `AUDIT` brings a second class so the chain clears 0.70; `CLEARING` brings a
# third and is what carries the flip. `REFUSED` is proposed and never committed -- a refused
# proposal returns before `append()`, so asserting its document is absent is what proves the
# refusal happened before the write and not after it.
AUDIT_ID = f"ev-{ENTITY}-audit"
CLEARING_ID = f"ev-{ENTITY}-clearing"
REFUSED_ID = f"ev-{ENTITY}-refused"
FLIPPED_STATUS = "CLEARED"

# The second scratch entity: no belief is ever written about it, because every claim made about
# it weighs 0.00. It exists so the counter can be driven without touching the chain above.
POISON_ENTITY = "verify-standing-counter"


class Failed(Exception):
    """A check did not hold. Raised so the cleanup in `finally` still runs."""


def check(condition: bool, message: str) -> None:
    if not condition:
        raise Failed(message)


def an_evidence(
    evidence_id: str,
    now: datetime,
    *,
    source_class: str = "verified_system_observation",
    entity: str = ENTITY,
) -> beliefs.Evidence:
    stamp = now.strftime(beliefs.TIMESTAMP)
    return beliefs.Evidence(
        id=evidence_id,
        # The class is part of the source, so two classes are two sources -- which is what
        # makes them independent in §4.3's noisy-OR rather than one sensor talking twice.
        source_id=f"firestore:{source_class}/{entity}",
        source_class=source_class,  # type: ignore[arg-type]
        observed_at=stamp,
        ingested_at=stamp,
        payload_hash=beliefs.payload_hash({"entity": entity, "evidence": evidence_id}),
        verifiable_by=f"re-read services/{entity}",
    )


async def propose(
    client: firestore.AsyncClient,
    evidence: list[beliefs.Evidence],
    *,
    now: datetime,
    status: str = STATUS,
    entity: str = ENTITY,
) -> policy.BeliefCommit:
    return await policy.commit(
        entity=entity,
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


async def refuse_if_agent_is_dirty(client: firestore.AsyncClient) -> None:
    """The standing half is only meaningful from a clean GOOD, and the restore has to be safe.

    `scripts/seed_registry.py` has no `--reset`, so a run that started from DEGRADED and
    restored what it found would cement it. Same reason `verify_denial_by_registry.py` refuses.
    """
    agent = await registry.get_agent(AGENT_ID, client=client)
    if agent.standing != "GOOD" or agent.rejection_window:
        raise Failed(
            f"{registry.COLLECTION}/{AGENT_ID} is {agent.standing} with "
            f"{len(agent.rejection_window)} rejection(s) on record. This script degrades it and "
            "restores GOOD with an empty window, which would erase that state -- reinstate the "
            "agent by hand first."
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
    for evidence_id in (*EVIDENCE_IDS, AUDIT_ID, CLEARING_ID, REFUSED_ID):
        await client.collection(beliefs.EVIDENCE_COLLECTION).document(evidence_id).delete()
    await client.collection(beliefs.COLLECTION).document(BELIEF_ID).delete()
    # The registry half. A direct write because `registry.py` has one standing writer and no
    # un-append path at all -- undoing a rejection is a test fixture's job, never the product's.
    print("--> restoring the agent: standing GOOD, empty rejection window")
    await (
        client.collection(registry.COLLECTION)
        .document(AGENT_ID)
        .update({"standing": "GOOD", "rejection_window": []})
    )


async def reinstate(client: firestore.AsyncClient) -> None:
    """Put the agent back to GOOD with an empty window. A direct write, deliberately.

    `registry.py` has one standing writer and no un-append path at all: §3.4 says restoration
    "requires explicit human reinstatement", and undoing a rejection is a test fixture's job,
    never the product's. This script is that fixture.
    """
    await (
        client.collection(registry.COLLECTION)
        .document(AGENT_ID)
        .update({"standing": "GOOD", "rejection_window": []})
    )


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

    print("==> proposing a status flip on one class alone -- 0.60 against a 0.70 door")
    flip = await propose(
        client, [an_evidence(EVIDENCE_IDS[2], latest)], now=latest, status="HEALTHY"
    )
    print(f"    {flip.outcome}/{flip.reason} at {flip.confidence:.2f}")
    # Item 14 gave this two doors and this is the *number*, not §6.3. One source class can never
    # reach 0.70 -- the strongest base weight is 0.60 and §4.3 collapses a class to its best item
    # -- so the same-class refusal only becomes reachable once the chain rests on two classes,
    # which is what `conflict_rule_checks` sets up. Both refusals, told apart by name.
    check(
        (flip.outcome, flip.reason) == ("REJECT", "BELOW_THRESHOLD"),
        f"the flip was {flip.outcome}/{flip.reason}, expected REJECT/BELOW_THRESHOLD",
    )
    check(
        flip.confidence < policy.FLIP_THRESHOLD,
        f"the flip was refused at {flip.confidence:.2f}, which is above 0.70 -- then the number "
        "was not what stopped it and this check is measuring something else",
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

    await conflict_rule_checks(client, stored_v1, latest)
    await standing_counter_checks(client, latest)


async def conflict_rule_checks(
    client: firestore.AsyncClient, stored_v1: dict[str, object] | None, latest: datetime
) -> None:
    """Item 14's verify line: a same-class flip above 0.70 is refused; a different class commits."""
    print("==> committing v4 -- a second source class, so the chain clears 0.70")
    audited = await propose(
        client, [an_evidence(AUDIT_ID, latest, source_class="third_party_audit")], now=latest
    )
    print(f"    {audited.outcome}/{audited.reason} v{audited.version} at {audited.confidence:.2f}")
    check(
        audited.outcome == "COMMIT", f"v4 was {audited.outcome}/{audited.reason}, expected COMMIT"
    )
    check(
        audited.confidence > policy.FLIP_THRESHOLD,
        f"v4 is at {audited.confidence:.2f}; the flip checks below need the chain above 0.70",
    )
    print(f"    ok  two classes accumulate to {audited.confidence:.2f} -- 1-(1-0.60)(1-0.55)")

    print("==> proposing a flip on a class already in the set -- above 0.70, still refused")
    same_class = latest + timedelta(hours=1)
    refused = await propose(
        client,
        [an_evidence(REFUSED_ID, same_class)],
        now=same_class,
        status=FLIPPED_STATUS,
    )
    print(f"    {refused.outcome}/{refused.reason} at {refused.confidence:.2f}")
    check(
        (refused.outcome, refused.reason) == ("REJECT", "FLIP_UNSUPPORTED"),
        f"the same-class flip was {refused.outcome}/{refused.reason}, "
        "expected REJECT/FLIP_UNSUPPORTED",
    )
    check(
        refused.confidence > policy.FLIP_THRESHOLD,
        f"the refusal was at {refused.confidence:.2f}, below 0.70 -- the number stopped it, "
        "not §6.3, so this run does not check what it claims to",
    )
    check(await raw_version(client, 5) is None, "the refused flip wrote a v5 anyway")
    refused_doc = await client.collection(beliefs.EVIDENCE_COLLECTION).document(REFUSED_ID).get()
    check(
        not refused_doc.exists,
        f"{REFUSED_ID} was written; a refusal must return before append(), not after",
    )
    print("    ok  one sensor cannot set and clear its own alarm (§6.3), and nothing was written")

    # Found by running this: the three refusals *this script deliberately provoked* --
    # NO_NEW_EVIDENCE, BELOW_THRESHOLD and FLIP_UNSUPPORTED -- are exactly §2.2 stage 6's three,
    # so the agent degraded in the middle of its own verification. That is the counter working,
    # and asserting it here is worth more than avoiding it: it proves live that the write is
    # real and that these three reasons are the ones that count. Then the agent is reinstated,
    # because the rest of this half needs the authority it just lost.
    print(
        "==> the refusals above have degraded the agent -- which is the point; checking, then reinstating"
    )
    provoked = await registry.get_agent(AGENT_ID, client=client)
    check(
        len(provoked.rejection_window) == 3,
        f"the three counted refusals left {len(provoked.rejection_window)} entries on the record",
    )
    check(
        provoked.standing == "DEGRADED",
        f"three counted refusals left standing at {provoked.standing}, expected DEGRADED",
    )
    check(
        [entry.reason for entry in provoked.rejection_window]
        == ["NO_NEW_EVIDENCE", "BELOW_THRESHOLD", "FLIP_UNSUPPORTED"],
        f"the window holds {[e.reason for e in provoked.rejection_window]!r}; expected the three "
        "refusals that are statements about the agent's evidence, in the order they happened",
    )
    print("    ok  §2.2 stage 6 wrote all three, and the third one degraded it (§3.4)")
    await reinstate(client)

    print("==> proposing the same flip on a genuinely different class -- §6.3's legitimate update")
    different = latest + timedelta(hours=2)
    stored_v4 = await raw_version(client, 4)
    flipped = await propose(
        client,
        [an_evidence(CLEARING_ID, different, source_class="contractual_record")],
        now=different,
        status=FLIPPED_STATUS,
    )
    print(f"    {flipped.outcome}/{flipped.reason} v{flipped.version} at {flipped.confidence:.2f}")
    check(
        (flipped.outcome, flipped.reason) == ("COMMIT", "ABOVE_THRESHOLD"),
        f"the different-class flip was {flipped.outcome}/{flipped.reason}, expected COMMIT",
    )
    stored_v5 = await raw_version(client, 5)
    check(stored_v5 is not None, "the flip committed but no version document was written")
    check(
        stored_v5 is not None and stored_v5["status"] == FLIPPED_STATUS,
        f"v5 stores status {stored_v5 and stored_v5.get('status')!r}, expected {FLIPPED_STATUS!r}",
    )
    check(
        stored_v5 is not None and abs(float(stored_v5["threshold"]) - policy.FLIP_THRESHOLD) < 1e-9,
        f"v5 stores threshold {stored_v5 and stored_v5.get('threshold')!r}, expected 0.70 -- the "
        "door it actually passed through",
    )
    check(
        stored_v5 is not None and stored_v5["evidence"] == [*EVIDENCE_IDS, AUDIT_ID, CLEARING_ID],
        f"v5 cites {stored_v5 and stored_v5.get('evidence')!r}, expected everything the chain "
        "ever rested on -- including the evidence for the status it overturned",
    )
    check(await raw_version(client, 4) == stored_v4, "v4 changed when the flip superseded it")
    check(await raw_version(client, 1) == stored_v1, "v1 changed when the flip was committed")
    print(
        f"    ok  v5 is {FLIPPED_STATUS} at threshold 0.70; v4 is byte-identical and still the trail"
    )


async def standing_counter_checks(client: firestore.AsyncClient, latest: datetime) -> None:
    """§2.2 stage 6 and §10's Standing row, against the live registry record.

    Three unverifiable claims about an entity with no belief: `unverified_external_claim`
    weighs 0.00, so the number never moves and nothing is ever written to the belief store.
    What changes is what the agent is permitted to do.
    """
    await reinstate(client)
    print(f"==> three unverifiable claims about {POISON_ENTITY} -- weight 0.00, all refused")
    for attempt in range(3):
        at = latest + timedelta(hours=3 + attempt)
        claim = await propose(
            client,
            [
                an_evidence(
                    f"ev-{POISON_ENTITY}-{attempt}",
                    at,
                    source_class="unverified_external_claim",
                    entity=POISON_ENTITY,
                )
            ],
            now=at,
            status="CLEARED",
            entity=POISON_ENTITY,
        )
        agent = await registry.get_agent(AGENT_ID, client=client)
        print(
            f"    attempt {attempt + 1}: {claim.outcome}/{claim.reason} at "
            f"{claim.confidence:.2f} -- window={len(agent.rejection_window)}, "
            f"standing={agent.standing}"
        )
        check(
            (claim.outcome, claim.reason) == ("REJECT", "BELOW_THRESHOLD"),
            f"attempt {attempt + 1} was {claim.outcome}/{claim.reason}, expected REJECT",
        )
        check(claim.confidence == 0.0, f"a bare assertion moved confidence to {claim.confidence}")
        check(
            len(agent.rejection_window) == attempt + 1,
            f"after {attempt + 1} refusal(s) the window holds {len(agent.rejection_window)}",
        )
        expected = "DEGRADED" if attempt == 2 else "GOOD"
        check(
            agent.standing == expected,
            f"after {attempt + 1} refusal(s) standing is {agent.standing}, expected {expected}",
        )
    print("    ok  the third refusal inside the window degraded the agent (§3.4)")

    print("==> a fourth claim, this one ordinary -- refused for who is asking, not what it says")
    ordinary = await propose(
        client,
        [
            an_evidence(
                f"ev-{POISON_ENTITY}-ordinary", latest + timedelta(hours=6), entity=POISON_ENTITY
            )
        ],
        now=latest + timedelta(hours=6),
        entity=POISON_ENTITY,
    )
    print(f"    {ordinary.outcome}/{ordinary.reason}")
    check(
        (ordinary.outcome, ordinary.reason) == ("REJECT", "STANDING_NOT_GOOD"),
        f"the fourth claim was {ordinary.outcome}/{ordinary.reason}, expected STANDING_NOT_GOOD",
    )
    after = await registry.get_agent(AGENT_ID, client=client)
    check(
        len(after.rejection_window) == 3,
        "an already-refused authority was counted as a fourth rejection",
    )
    check(
        await beliefs_absent(client, POISON_ENTITY),
        f"a belief about {POISON_ENTITY} was written; every claim about it weighed 0.00",
    )
    print("    ok  a DEGRADED agent's memory writes are rejected outright, and nothing was learned")


async def beliefs_absent(client: firestore.AsyncClient, entity: str) -> bool:
    snapshot = await client.collection(beliefs.COLLECTION).document(f"belief-{entity}").get()
    return not snapshot.exists


async def run(project_id: str) -> int:
    client = firestore.AsyncClient(project=project_id)
    await refuse_if_dirty(client)
    await refuse_if_agent_is_dirty(client)
    try:
        await checks(client)
    except Failed as exc:
        print(f"FAIL: {exc}", file=sys.stderr)
        return 1
    finally:
        await cleanup(client)
    print(
        f"==> done. {BELIEF_ID} flipped on a different class, refused on the same one, "
        f"{AGENT_ID} degraded and reinstated, and the scratch state is gone."
    )
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
