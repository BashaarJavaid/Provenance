#!/usr/bin/env python3
"""Seed §6.2's class belief: three entity beliefs, one Memory Analyst, one generalization.

    GOOGLE_CLOUD_PROJECT=provenance-hackathon GOOGLE_GENAI_USE_VERTEXAI=1 \
      GOOGLE_CLOUD_LOCATION=global .venv/bin/python scripts/seed_class_belief.py

ROADMAP item 23. Two phases, one script, because the second depends on the first and two
scripts over one dependent chain drift (`verify_refuted.py` says the same thing about
teardowns):

  1. One `CONFIG_REGRESSION_PRONE` entity belief on each of `checkout-api`, `orders-api` and
     `search-api`, committed through the real `policy.commit()` as `sre-infra-agent`. Each
     rests on one fresh `verified_system_observation`, so each lands at **0.60**.
  2. The Memory Analyst (§5.9) reads those three and returns a class name and one sentence --
     and nothing else. `derived_from` is what this script selected mechanically, the evidence
     set is derived from the constituents inside §2.2, and the number is §4.3 capped by §6.2:
     `min(0.60, 0.75, 0.60 - 0.05)` = **0.55**.

Why these three services: `inventory-api`'s belief is created and deleted by every run of
`verify_incident_one.py`, so a class belief derived from it would dangle after the next
regression run, and `pricing-api` must stay belief-free or item 24 -- a deviation on an entity
with empty entity memory -- proves nothing. The other two exist in the fixture for exactly this.

Create-if-absent and **deliberately no `--reset`**, `seed_belief.py`'s posture: item 24's beat
is this belief firing on a service the fleet has never handled, and a re-run that rewrote the
chain would erase whatever that beat left behind. It refuses outright if the class belief
exists. The three constituents are create-if-absent too -- a second run over an existing
constituent is refused `NO_NEW_EVIDENCE` by §2.2 stage 3, which is the store defending itself.

Costs one `gemini-2.5-pro` call. Needs credentials, so it is not in CI; the offline half is
the item-23 section of `tests/test_policy.py` and the `verify:` line is
`scripts/verify_class_belief.py`.
"""

from __future__ import annotations

import asyncio
import os
import sys
from datetime import UTC, datetime
from typing import Any

from google.adk.runners import Runner
from google.adk.sessions import InMemorySessionService
from google.cloud import firestore
from google.genai import types
from opentelemetry import trace

from provenance import beliefs, incident, models, policy, telemetry
from provenance.agents import memory_analyst
from provenance.synthetic import company

DOMAIN = "infrastructure"
CONSTITUENT_AGENT = "sre-infra-agent"
STATUS = incident.BELIEF_STATUS
# The three tier-2 services no verify script's teardown touches. `checkout-api` has been in
# the fixture since item 4; `orders-api` and `search-api` arrived with item 23 for this.
CONSTITUENTS = ("checkout-api", "orders-api", "search-api")
_APP = "provenance-seed"


class Failed(Exception):
    """A check did not hold."""


def check(condition: bool, message: str) -> None:
    if not condition:
        raise Failed(message)


def an_observation(entity: str, at: datetime) -> beliefs.Evidence:
    """One typed reading of a service (§3.3), content-addressed like every other."""
    source_id = f"firestore:services/{entity}"
    stamp = at.strftime(beliefs.TIMESTAMP)
    service = company.service(entity)
    return beliefs.Evidence(
        id=beliefs.evidence_id(source_id, stamp),
        source_id=source_id,
        source_class="verified_system_observation",
        observed_at=stamp,
        ingested_at=stamp,
        payload_hash=beliefs.payload_hash(
            {"entity": entity, "error_rate": service.error_rate, "at": stamp}
        ),
        verifiable_by=f"re-read services/{entity}",
    )


async def refuse_if_seeded(client: firestore.AsyncClient, belief_id: str) -> None:
    """No --reset, for `seed_belief.py`'s reason: item 24's beat runs against this belief."""
    try:
        existing = await beliefs.current(belief_id, client=client)
    except beliefs.BeliefNotFound:
        return
    raise Failed(
        f"{beliefs.COLLECTION}/{belief_id} already exists at v{existing.version} "
        f"({existing.status}, conf {existing.confidence:.3f}). This script is create-if-absent "
        "and has no --reset. Delete it by hand if you genuinely want a fresh generalization."
    )


async def seed_constituents(client: firestore.AsyncClient, now: datetime) -> tuple[str, ...]:
    """Phase 1. Three entity beliefs at 0.60, each on one fresh verified system observation."""
    ids = []
    for entity in CONSTITUENTS:
        belief_id = beliefs.belief_id_for(entity)
        try:
            existing = await beliefs.current(belief_id, client=client)
        except beliefs.BeliefNotFound:
            pass
        else:
            # Genuinely create-if-absent. Leaving this to §2.2's novelty check does not work:
            # a re-run observes at a *new* timestamp, so the pair is novel and the constituent
            # gains a v2 saying nothing v1 did not. `seed_firestore.py`'s "exists", here.
            print(f"    {entity:<14} exists   v{existing.version} at {existing.confidence:.4f}")
            check(
                existing.status == STATUS,
                f"{entity} already holds {existing.status}, not the status being generalized",
            )
            ids.append(belief_id)
            continue
        result = await policy.commit(
            entity=entity,
            domain=DOMAIN,
            status=STATUS,
            evidence=[an_observation(entity, now)],
            agent_id=CONSTITUENT_AGENT,
            now=now,
            client=client,
        )
        print(
            f"    {entity:<14} {result.outcome}/{result.reason} v{result.version} "
            f"at {result.confidence:.4f}"
        )
        check(
            result.outcome == "COMMIT",
            f"{entity} was not committed: {result.outcome}/{result.reason}",
        )
        ids.append(belief_id)
    return tuple(ids)


def render(versions: tuple[beliefs.BeliefVersion, ...]) -> str:
    """What the Analyst is shown. Written by code, so no model chooses its own input."""
    lines = []
    for version in versions:
        service = company.service(version.entity)
        lines.append(
            f"- {version.entity} ({service.name}, a {service.tier} service: "
            f"{service.description}) is {version.status}, believed at confidence "
            f"{version.confidence:.2f} since {version.committed_at}, on a "
            f"verified_system_observation of the service itself"
        )
    return "\n".join(lines)


# What `CONFIG_REGRESSION_PRONE` records, in a sentence. Written here rather than left for the
# model to infer from the constant's spelling: the status is committed by the control loop only
# when a rollback executed and the Verification Agent CONFIRMED it against a pre-declared
# predicate (§7.2), which is a fact about this system and not something to be guessed at. This
# is `sre_infra.seed_state()`'s `planner_context` posture -- code states what is known, the
# model generalizes over it. Without it the Analyst has three rows differing only by name and
# reaches for whatever they share, which live turned out to be the word "API".
STATUS_MEANING = (
    f"{STATUS} is committed about a service only after an error-rate deviation was observed, "
    "a rollback of its configuration to the last known-good version was executed, and a "
    "verification against a predicate declared before execution CONFIRMED that the deviation "
    "was gone afterwards. It is a claim about configuration changes causing error-rate "
    "deviations on that service, established by rolling one back."
)


async def generalize(versions: tuple[beliefs.BeliefVersion, ...]) -> tuple[str, str]:
    """Phase 2's model call. It returns a class name and a sentence, and nothing else."""
    agent = memory_analyst.build(
        models.ANALYST,
        agent_id=memory_analyst.AGENT_ID,
        agent_version=memory_analyst.AGENT_VERSION,
    )
    sessions = InMemorySessionService()
    session_id = "seed-class-belief"
    await sessions.create_session(
        app_name=_APP,
        user_id=session_id,
        session_id=session_id,
        state={"constituents": render(versions), "status_meaning": STATUS_MEANING},
    )
    runner = Runner(node=agent, app_name=_APP, session_service=sessions)
    async for _ in runner.run_async(
        user_id=session_id,
        session_id=session_id,
        new_message=types.Content(role="user", parts=[types.Part(text=STATUS)]),
    ):
        pass
    session = await sessions.get_session(app_name=_APP, user_id=session_id, session_id=session_id)
    output: Any = {} if session is None else session.state.get(memory_analyst.OUTPUT_KEY, {})
    belief_class = str(output.get("belief_class", "")).strip()
    statement = str(output.get("statement", "")).strip()
    check(bool(belief_class), "the Analyst returned no class name")
    check(bool(statement), "the Analyst returned no statement")
    # §5.9: it recommends and never asserts a number. `Generalization` has no field for one,
    # so this only has to hold that it did not smuggle one into the sentence as a decimal.
    check(
        "confiden" not in statement.lower(),
        f"the Analyst asserted a confidence in its statement: {statement!r}",
    )
    return belief_class, statement


async def read_back(client: firestore.AsyncClient, belief_id: str, ids: tuple[str, ...]) -> None:
    """Every claim, re-read out of Firestore and the arithmetic re-derived from the citations."""
    version = await beliefs.current(belief_id, client=client)
    check(version.scope == "CLASS", f"scope is {version.scope}")
    check(version.version == 1, f"landed as v{version.version}")
    check(tuple(version.derived_from) == ids, f"derived_from is {version.derived_from}")
    check(bool(version.statement), "the stored version carries no statement")
    check(version.threshold == policy.NEW_BELIEF_THRESHOLD, f"faced {version.threshold}")

    constituents = [await beliefs.current(one, client=client) for one in ids]
    items = await beliefs.read_evidence(version.evidence_ids, client=client)
    cited = {i for c in constituents for i in c.evidence_ids}
    check(
        set(version.evidence_ids) == cited,
        "the class belief does not cite exactly what its constituents rest on",
    )

    at = datetime.strptime(version.committed_at, beliefs.TIMESTAMP).replace(tzinfo=UTC)
    uncapped = policy.confidence(items, domain=DOMAIN, now=at)
    by_id = {item.id: item for item in items}
    weakest = min(
        policy.confidence([by_id[i] for i in c.evidence_ids], domain=DOMAIN, now=at)
        for c in constituents
    )
    expected = min(uncapped, policy.CLASS_CAP, weakest - policy.CLASS_MARGIN)
    print(f"    uncapped §4.3 over {len(items)} items      {uncapped:.4f}")
    print(f"    weakest constituent                  {weakest:.4f}")
    print(
        f"    min(that, {policy.CLASS_CAP}, weakest - {policy.CLASS_MARGIN})       {expected:.4f}"
    )
    # One second of decay against a 30-day half-life is under 1e-7; `committed_at` is
    # truncated to the second while `commit()` computed at a `now` carrying microseconds.
    check(
        abs(expected - version.confidence) < 1e-6,
        f"the cap gives {expected}, the version stores {version.confidence}",
    )
    check(version.confidence < weakest, "a generalization is at least as certain as its parts")
    check(version.confidence <= policy.CLASS_CAP, "the ceiling did not bind")

    # §6.6's index reads root documents, so the statement has to be on one or item 24's
    # nomination finds nothing. This is the one place that is checkable before item 24 runs.
    indexed = dict(await beliefs.class_statements(client=client))
    check(belief_id in indexed, f"{belief_id} is not in the recall index")
    check(indexed[belief_id] == version.statement, "the indexed statement is not the stored one")


async def run(project_id: str) -> int:
    client = firestore.AsyncClient(project=project_id)
    now = datetime.now(UTC)

    print("--> phase 1: the constituents")
    ids = await seed_constituents(client, now)
    versions = tuple([await beliefs.current(one, client=client) for one in ids])

    print(f"--> phase 2: the Memory Analyst ({models.ANALYST})")
    belief_class, statement = await generalize(versions)
    belief_id = beliefs.belief_id_for(belief_class)
    print(f"    class:     {belief_class}")
    print(f"    statement: {statement}")
    await refuse_if_seeded(client, belief_id)

    result = await policy.commit(
        entity=belief_class,
        domain=DOMAIN,
        status=STATUS,
        evidence=[],
        agent_id=memory_analyst.AGENT_ID,
        now=now,
        client=client,
        scope="CLASS",
        statement=statement,
        derived_from=ids,
    )
    print(f"    {result.outcome}/{result.reason} v{result.version} at {result.confidence:.4f}")
    check(result.outcome == "COMMIT", f"refused: {result.outcome}/{result.reason}")

    print("--> reading the chain back out of Firestore")
    await read_back(client, belief_id, ids)
    print(f"==> done. {belief_id} is ADVISORY ONLY at {result.confidence:.4f}.")
    return 0


def main() -> int:
    project_id = os.environ.get("GOOGLE_CLOUD_PROJECT")
    if not project_id:
        print("FAIL: GOOGLE_CLOUD_PROJECT is not set.", file=sys.stderr)
        print(
            "      GOOGLE_CLOUD_PROJECT=provenance-hackathon GOOGLE_GENAI_USE_VERTEXAI=1"
            " GOOGLE_CLOUD_LOCATION=global .venv/bin/python scripts/seed_class_belief.py",
            file=sys.stderr,
        )
        return 1
    # Without this the tracer is a no-op and the Analyst's reasoning span goes nowhere --
    # item 21 lost a run to exactly that.
    telemetry.configure_tracing()
    print(f"==> seeding a class belief -> {project_id}   (by {memory_analyst.AGENT_ID})")
    try:
        code = asyncio.run(run(project_id))
    except Failed as exc:
        print(f"FAIL: {exc}", file=sys.stderr)
        return 1
    finally:
        # Or the flush races BatchSpanProcessor's queue and the Analyst's span never ships --
        # item 21's second defect, in the same place.
        trace.get_tracer_provider().force_flush()  # type: ignore[attr-defined]
    return code


if __name__ == "__main__":
    raise SystemExit(main())
