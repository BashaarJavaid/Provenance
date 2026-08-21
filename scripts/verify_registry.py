#!/usr/bin/env python3
"""Check ROADMAP item 5's `verify:` line against real Firestore: flip standing mid-run and
the next read reflects it.

    GOOGLE_CLOUD_PROJECT=provenance-hackathon .venv/bin/python scripts/verify_registry.py

ARCHITECTURE.md §1.1's fourth load-bearing property is the one being checked, and its two
§10 rows are Gateway (registry read at request time) and Standing. The check is meaningful
only because everything happens in **one process against one client**: the flip is written
and re-read without restarting anything, so a `get_agent` that memoized -- at import, in a
dict, behind an lru_cache -- would return the stale value and this script would exit 1.

The record is restored to whatever standing it started with, so a run leaves no trace. Not
run in CI: CI has no credentials. The offline half is `tests/test_registry.py`.
"""

from __future__ import annotations

import asyncio
import os
import sys

from google.cloud import firestore

from provenance import registry
from provenance.telemetry import Standing

AGENT_ID = "sre-infra-agent"


async def run(project_id: str) -> int:
    # One client, one process, no restart between the reads. That is the whole test.
    client = firestore.AsyncClient(project=project_id)

    before = await registry.get_agent(AGENT_ID, client=client)
    print(f"==> {registry.COLLECTION}/{AGENT_ID} standing={before.standing}")

    # Flip to something it is not, so the check can never pass by accident.
    target: Standing = "DEGRADED" if before.standing != "DEGRADED" else "GOOD"
    print(f"--> set_standing({target})")
    await registry.set_standing(AGENT_ID, target, client=client)

    after = await registry.get_agent(AGENT_ID, client=client)
    print(f"==> re-read standing={after.standing}   (same process, same client)")

    print(f"--> restoring to {before.standing}")
    await registry.set_standing(AGENT_ID, before.standing, client=client)
    restored = await registry.get_agent(AGENT_ID, client=client)

    if after.standing != target:
        print(
            f"FAIL: the re-read still says {after.standing!r}; the registry is being cached.",
            file=sys.stderr,
        )
        return 1
    if restored.standing != before.standing:
        print(
            f"FAIL: restore left standing at {restored.standing!r}, not {before.standing!r}.",
            file=sys.stderr,
        )
        return 1

    print(
        f"==> done. the flip was visible on the next read; {AGENT_ID} is back at "
        f"{restored.standing}."
    )
    return 0


def main() -> int:
    project_id = os.environ.get("GOOGLE_CLOUD_PROJECT")
    if not project_id:
        print("FAIL: GOOGLE_CLOUD_PROJECT is not set.", file=sys.stderr)
        print("      Re-run with:", file=sys.stderr)
        print(
            "        GOOGLE_CLOUD_PROJECT=provenance-hackathon"
            " .venv/bin/python scripts/verify_registry.py",
            file=sys.stderr,
        )
        return 1
    try:
        return asyncio.run(run(project_id))
    except registry.AgentNotRegistered:
        print(f"FAIL: {AGENT_ID} is not registered. Seed it first:", file=sys.stderr)
        print(
            f"        GOOGLE_CLOUD_PROJECT={project_id} .venv/bin/python scripts/seed_registry.py",
            file=sys.stderr,
        )
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
