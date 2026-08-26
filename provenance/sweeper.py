"""The Staleness Sweeper — §5.11 and §6.5's clock, running (item 29).

"`Valid until` is worthless if nothing consumes it." Every version the Policy Engine has
written since item 12 carries an `expires_at`; until this module there was nothing that read
one. An organization that cannot tell "we know this is fine" from "we last checked six weeks
ago" does not have institutional memory — it has a log.

What runs is §6.5's **no-branch, and only that**. The yes-branch asks whether a re-verification
source is available, and this system has none: the Verification Agent judges a predicate
declared *before* an execution, and a sweep has neither. Building one would have meant
inventing a source §6.5 does not define, which is the failure ADR-029 named — tuning the fleet
until it produces the demo. `docs/adr/ADR-031` records the absence rather than papering it.

Two things this module deliberately does not do:

  * **It decides nothing.** The eligibility rule lives in `policy.expire()`, which re-reads the
    version in force and applies the clock itself. This module finds candidates and calls the
    door — the same division §1.1 property 2 draws everywhere else, with the walk in the place
    a proposer would be. A sweep is not exempt from the Policy Engine being the authority over
    what the organization believes.
  * **It never deletes.** §6.5 says so twice and the store could not do it anyway: `beliefs`
    appends and nothing under `provenance/` modifies or removes a version. A swept belief keeps
    every version it ever had; recall stops handing it over (`recall.DROPPED_STATUSES`), which
    is a different thing from it being gone.

The loop is started by `app.py`'s lifespan and is one of the two long-running async behaviours
the track's runtime requirement asks for. **It runs only while a Cloud Run instance is warm**,
because the service is deployed at `--min-instances=0` and that is a cost posture rather than
an oversight — so "runs continuously" is true of the process and not of the calendar. The ADR
states the limit; scripts and any on-camera beat call `sweep()` directly rather than waiting
for a tick.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from provenance import beliefs, policy

_log = logging.getLogger(__name__)

# One tick every five minutes. The walk is one collection stream plus a `current()` per belief
# — roughly a dozen reads at this store's size — so five minutes is ~3k reads/day even with a
# demo tab pinned open holding the instance warm, which leaves the registry panel's budget
# (ADR-030 §7) intact. A minute would be four times that for a loop nothing waits on: the
# verify script and the demo call `sweep()` directly.
SWEEP_INTERVAL_SECONDS = 300


@dataclass(frozen=True)
class Swept:
    """What one tick did. Counts only — the beliefs themselves are the store's business."""

    examined: int
    expired: tuple[str, ...]
    skipped: tuple[str, ...]


async def sweep(*, now: datetime, client: Any | None = None) -> Swept:
    """Walk every belief, downgrade the ones whose clock has run out. One tick.

    ponytail: N+1 — one stream of the root collection, then `current()` per belief. At a store
    holding a handful of beliefs that is a dozen reads; the upgrade path if it ever matters is a
    collection-group query on `versions` filtered by `expires_at`, which needs a composite index
    and still needs `current()` per hit to check the version it found is the one in force.
    Mirroring `expires_at` onto the root document would make it one query and is the one thing
    that must not happen: ADR-005's guarantee is that the recall index reads root documents and
    therefore *cannot* see currency, even by accident.

    A belief that cannot be read or written is skipped and left exactly as it was — still past
    its clock, so the next tick sweeps it again. Nothing is half-written, and one unreadable
    belief does not stop the other nine (§7.3).
    """
    expired: list[str] = []
    skipped: list[str] = []
    ids = await beliefs.belief_ids(client=client)
    for belief_id in ids:
        try:
            outcome = await policy.expire(belief_id=belief_id, now=now, client=client)
        except beliefs.BeliefStoreError as exc:
            # `expire()` raises only where it could not read the version in force — there is no
            # entity and no status to report a decision about, so there is no decision and no
            # span. Everything it *decided*, refusals included, comes back as an outcome.
            _log.warning("sweep: %s unreadable, skipped (%s)", belief_id, exc)
            skipped.append(belief_id)
            continue
        if outcome.outcome == "EXPIRE":
            expired.append(belief_id)
        elif outcome.reason != "NOT_DUE":
            _log.warning("sweep: %s refused %s", belief_id, outcome.reason)
            skipped.append(belief_id)
    return Swept(examined=len(ids), expired=tuple(expired), skipped=tuple(skipped))


async def run_forever(*, interval: float = SWEEP_INTERVAL_SECONDS) -> None:
    """§5.11's long-running process. Started by `app.py`'s lifespan, cancelled on shutdown.

    Nothing escapes this loop except cancellation: a tick that raises is a tick that logged and
    will happen again in five minutes, and the alternative — an exception killing the task —
    is a service that silently stops consuming expiry for the rest of its life.
    """
    while True:
        await asyncio.sleep(interval)
        try:
            swept = await sweep(now=datetime.now(UTC))
        except Exception:  # noqa: BLE001 — see the docstring: the loop outlives every tick
            _log.exception("sweep: tick failed")
            continue
        if swept.expired:
            _log.info("sweep: expired %s", ", ".join(swept.expired))


async def cancel(task: asyncio.Task[None]) -> None:
    """Stop the loop and wait for it. Cancellation is the only way out of `run_forever()`."""
    task.cancel()
    with contextlib.suppress(asyncio.CancelledError):
        await task
