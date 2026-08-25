#!/usr/bin/env python3
"""Check ROADMAP item 23's `verify:` line live: a class belief can never become authority.

    GOOGLE_CLOUD_PROJECT=provenance-hackathon GOOGLE_GENAI_USE_VERTEXAI=1 \
      .venv/bin/python scripts/verify_class_belief.py

Four things, and the third is the item's line:

  [1] the stored class belief's number is `min(§4.3 over the union, CLASS_CAP,
      weakest constituent - CLASS_MARGIN)`, re-derived here from first principles rather than
      by calling `policy.contributions()` -- `verify_belief_inspector.py`'s rule, so this is
      not asserting that a function equals itself;
  [2] a **real** `text-embedding-005` nominates it for an incident on `pricing-api`, an entity
      with no beliefs of its own, and it arrives in `Recalled.class_beliefs` and never in
      `entity_ids`. That is item 24's premise, checked here so item 24 is not the first place
      it can fail;
  [3] an entity commit citing it as evidence is refused `CLASS_BELIEF_NOT_EVIDENCE`, writes no
      version and no evidence document, and costs the proposing agent exactly one window entry;
  [4] a class proposal with two constituents is refused `INSUFFICIENT_CONSTITUENTS` at no cost
      to standing.

`verify_supply_chain.py`'s posture: it has no `refuse_if_dirty()` because there is no fault to
inject and nothing to undo, and it guards the opposite -- the class belief's chain is
byte-identical before and after, since this is the one script that provokes refusals against it.
The one thing it does write is the proposing agent's rejection window, restored in a
`try/finally` on any exit path including Ctrl-C.

Requires `scripts/seed_class_belief.py` to have run. Costs two embedding calls and no
reasoning-model calls. Needs credentials, so it is not in CI.
"""

from __future__ import annotations

import asyncio
import os
import sys
from dataclasses import asdict
from datetime import UTC, datetime

from google.cloud import firestore

from provenance import beliefs, incident, policy, recall, registry
from provenance.agents import memory_analyst
from provenance.synthetic import company

DOMAIN = "infrastructure"
AGENT_ID = memory_analyst.AGENT_ID
STATUS = incident.BELIEF_STATUS
# Item 24's subject: a tier-2 service with no config history and no beliefs of its own.
UNSEEN = "pricing-api"
SPIKED = 0.38
# Scratch entities. Neither is in the entity model, and neither is ever written: both exist
# only to carry a refused proposal.
SCRATCH_ENTITY = "verify-class-belief"
SCRATCH_CLASS = "service.verify_class_belief"


class Failed(Exception):
    """A check did not hold."""


def check(condition: bool, message: str) -> None:
    if not condition:
        raise Failed(message)
    print(f"    ok: {message}")


async def the_class_belief(client: firestore.AsyncClient) -> beliefs.BeliefVersion:
    """The one CLASS belief in the store. Found through the index, not by a name typed here.

    `seed_class_belief.py` lets the Analyst write the class name, so hard-coding
    `service.config_deploy` would make this script pass or fail on what a model chose to call
    it rather than on what the engine did with it.
    """
    indexed = [belief_id for belief_id, _ in await beliefs.class_statements(client=client)]
    check(
        len(indexed) == 1,
        f"exactly one class belief is in the store: {indexed}",
    )
    return await beliefs.current(indexed[0], client=client)


async def check_arithmetic(client: firestore.AsyncClient, version: beliefs.BeliefVersion) -> None:
    """[1] §6.2's cap, re-derived rather than re-called."""
    print("\n[1] the number is §4.3 capped by §6.2, and both caps are checkable")
    check(
        len(version.derived_from) >= policy.CLASS_MIN_CONSTITUENTS,
        f"it generalizes {len(version.derived_from)} entity beliefs (§6.2 asks for "
        f"{policy.CLASS_MIN_CONSTITUENTS})",
    )
    constituents = [await beliefs.current(one, client=client) for one in version.derived_from]
    check(
        all(c.scope == "ENTITY" and c.status == version.status for c in constituents),
        "every constituent is a current entity belief carrying the status being generalized",
    )

    items = await beliefs.read_evidence(version.evidence_ids, client=client)
    check(
        set(version.evidence_ids) == {i for c in constituents for i in c.evidence_ids},
        "it cites exactly the union of what its constituents rest on, and nothing of its own",
    )

    # §4.3 from first principles: the least-decayed item per distinct source class, noisy-OR.
    at = datetime.strptime(version.committed_at, beliefs.TIMESTAMP).replace(tzinfo=UTC)
    half_life = policy.HALF_LIFE_DAYS[version.domain]

    def noisy_or(evidence: list[beliefs.Evidence]) -> float:
        strongest: dict[str, float] = {}
        for item in evidence:
            age = (
                at - datetime.strptime(item.observed_at, beliefs.TIMESTAMP).replace(tzinfo=UTC)
            ).total_seconds() / 86400
            weight = policy.BASE_WEIGHT[item.source_class] * 2 ** (-max(age, 0.0) / half_life)
            strongest[item.source_class] = max(strongest.get(item.source_class, 0.0), weight)
        product = 1.0
        for weight in strongest.values():
            product *= 1 - weight
        return 1 - product

    by_id = {item.id: item for item in items}
    uncapped = noisy_or(list(items))
    per_constituent = {
        c.belief_id: noisy_or([by_id[i] for i in c.evidence_ids]) for c in constituents
    }
    weakest = min(per_constituent.values())
    expected = min(uncapped, policy.CLASS_CAP, weakest - policy.CLASS_MARGIN)
    print(f"    uncapped §4.3            {uncapped:.4f}")
    for belief_id, value in per_constituent.items():
        print(f"    {belief_id:<28} {value:.4f}")
    print(f"    weakest - {policy.CLASS_MARGIN}            {weakest - policy.CLASS_MARGIN:.4f}")
    print(f"    ceiling                  {policy.CLASS_CAP:.4f}")
    print(f"    stored                   {version.confidence:.4f}")
    check(
        abs(expected - version.confidence) < 1e-6,
        f"the stored number is the cap applied to §4.3: {expected:.4f}",
    )
    check(
        version.confidence < weakest,
        "and it is strictly below its weakest constituent, so generalizing never adds certainty",
    )
    check(
        version.confidence <= policy.CLASS_CAP, f"it is at or under the {policy.CLASS_CAP} ceiling"
    )


async def check_recall(client: firestore.AsyncClient, version: beliefs.BeliefVersion) -> None:
    """[2] item 24's premise: it fires on an entity with empty entity memory."""
    print(f"\n[2] a real embedding model nominates it for a deviation on {UNSEEN}")
    service = company.service(UNSEEN)
    query = recall.query_text(
        target=UNSEEN,
        signal="error_rate",
        kind="service",
        tier=service.tier,
        description=service.description,
        observed_value=SPIKED,
    )
    recalled = await recall.recall(UNSEEN, query, client=client)
    check(
        version.belief_id in recalled.nominated_ids,
        f"the index nominated it for {UNSEEN}: {recalled.nominated_ids}",
    )
    check(
        [b.belief_id for b in recalled.class_beliefs] == [version.belief_id],
        "and the store handed it over as a class belief",
    )
    check(
        recalled.entity_ids == (),
        f"{UNSEEN} has no entity beliefs at all, which is what makes item 24's beat a beat",
    )
    # §6.2's cap in the type: `entity_ids` is what `authorizations/{id}` cites, so a class
    # belief appearing there would make a §6.4 retraction flag actions on grounds §6.2 says
    # they could not have had.
    check(
        version.belief_id not in recalled.entity_ids,
        "a class belief is never among the ids an authorized action may rest on",
    )
    check(
        "ADVISORY ONLY" in recalled.summary(),
        "and the text a reasoning agent is shown says so on its face",
    )


async def check_refusals(client: firestore.AsyncClient, version: beliefs.BeliefVersion) -> None:
    """[3] and [4]: the engine refusing, and what each refusal costs."""
    print("\n[3] citing it as evidence for an entity belief is refused by the Policy Engine")
    now = datetime.now(UTC)
    stamp = now.strftime(beliefs.TIMESTAMP)
    laundered = beliefs.Evidence(
        id=beliefs.evidence_id(version.belief_id, stamp),
        source_id=version.belief_id,
        source_class="verified_system_observation",
        observed_at=stamp,
        ingested_at=stamp,
        payload_hash=beliefs.payload_hash({"belief": version.belief_id}),
        verifiable_by="re-read the class belief",
    )
    result = await policy.commit(
        entity=SCRATCH_ENTITY,
        domain=DOMAIN,
        status=STATUS,
        evidence=[laundered],
        agent_id=AGENT_ID,
        now=now,
        client=client,
    )
    print(f"    {result.outcome}/{result.reason} at {result.confidence:.2f}")
    check(
        (result.outcome, result.reason) == ("REJECT", "CLASS_BELIEF_NOT_EVIDENCE"),
        "the proposal was refused for the reason §6.2 gives",
    )
    try:
        await beliefs.current(beliefs.belief_id_for(SCRATCH_ENTITY), client=client)
        raise Failed("a refused commit wrote a version")
    except beliefs.BeliefNotFound:
        check(True, "no version was written")
    try:
        await beliefs.read_evidence([laundered.id], client=client)
        raise Failed("a refused commit wrote its evidence document")
    except beliefs.BeliefNotFound:
        check(True, "and no evidence document either -- the refusal is before any write")

    agent = await registry.get_agent(AGENT_ID, client=client)
    check(
        [entry.reason for entry in agent.rejection_window] == ["CLASS_BELIEF_NOT_EVIDENCE"],
        "it cost the proposing agent exactly one window entry (§3.4)",
    )
    check(agent.standing == "GOOD", "one rejection is not three, so standing is unchanged")

    print("\n[4] and two entity beliefs are not a generalization")
    short = await policy.commit(
        entity=SCRATCH_CLASS,
        domain=DOMAIN,
        status=version.status,
        evidence=[],
        agent_id=AGENT_ID,
        now=now,
        client=client,
        scope="CLASS",
        statement="Two of anything is a coincidence.",
        derived_from=list(version.derived_from)[:2],
    )
    print(f"    {short.outcome}/{short.reason}")
    check(
        (short.outcome, short.reason) == ("REJECT", "INSUFFICIENT_CONSTITUENTS"),
        f"§6.2's minimum of {policy.CLASS_MIN_CONSTITUENTS} is enforced by the engine",
    )
    try:
        await beliefs.current(beliefs.belief_id_for(SCRATCH_CLASS), client=client)
        raise Failed("a refused class proposal wrote a version")
    except beliefs.BeliefNotFound:
        check(True, "no version was written")
    agent = await registry.get_agent(AGENT_ID, client=client)
    check(
        len(agent.rejection_window) == 1,
        "and it cost no standing: how many beliefs exist is a fact about the store, not "
        "about the honesty of the proposal (§3.4)",
    )


async def reinstate(client: firestore.AsyncClient) -> None:
    """A direct write. `registry.py` has one standing writer and no un-append path at all --
    §3.4 makes restoration a human act, so undoing a rejection is a fixture's job."""
    print("\n--> restoring the agent: standing GOOD, empty rejection window")
    await (
        client.collection(registry.COLLECTION)
        .document(AGENT_ID)
        .update({"standing": "GOOD", "rejection_window": []})
    )


async def run(project_id: str) -> int:
    client = firestore.AsyncClient(project=project_id)
    agent = await registry.get_agent(AGENT_ID, client=client)
    check(
        agent.standing == "GOOD" and not agent.rejection_window,
        f"{AGENT_ID} starts GOOD with an empty window",
    )

    version = await the_class_belief(client)
    print(f"==> {version.belief_id} v{version.version}: {version.statement}")
    before = [asdict(v) for v in await beliefs.history(version.belief_id, client=client)]

    await check_arithmetic(client, version)
    await check_recall(client, version)
    try:
        await check_refusals(client, version)
    finally:
        await reinstate(client)

    # The point of this script having no teardown: it must leave the belief exactly as it
    # found it, because items 24 and 27/28 run against this chain.
    after = [asdict(v) for v in await beliefs.history(version.belief_id, client=client)]
    check(before == after, "the class belief's chain is byte-identical to how it started")
    print(
        "\nPASS: the cap is arithmetic, the index nominates it on an entity with no memory, "
        "and the Policy Engine refuses to let it become evidence."
    )
    return 0


def main() -> int:
    project_id = os.environ.get("GOOGLE_CLOUD_PROJECT")
    if not project_id:
        print("FAIL: GOOGLE_CLOUD_PROJECT is not set.", file=sys.stderr)
        print(
            "      GOOGLE_CLOUD_PROJECT=provenance-hackathon GOOGLE_GENAI_USE_VERTEXAI=1"
            " .venv/bin/python scripts/verify_class_belief.py",
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
