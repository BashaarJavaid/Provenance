"""The skeleton service: a health endpoint and the UI shell, deployed on day one.

`ARCHITECTURE.md` §11 stands Cloud Run up in Phase 1 "not at the end" because the trace
UI (item 11), the approval queue (item 30), and the cold-visitor test (item 36) all
assume a live URL to build on. This module is that URL and nothing more.

`POST /trigger` arrived with item 9 and is the "live trigger stream" §5.3 names. It is the
*wake* signal, not an action endpoint: it hands a `Trigger` to the control loop and returns
what the gateway decided. There is still no route that authorizes anything — the gateway is
a pipeline (§2.1), reached only through `incident.run_incident`, and §1.1 property 1 holds
because this module has no other way in. ADK routes and delegates; it does not serve this
app (`docs/adr/ADR-007`, ADR-008).

The trigger is guarded by a shared secret rather than left open. The service is public and
unauthenticated by design (item 36's cold judge), and every trigger spends model tokens
against a fixed credit; an open endpoint is a loop somebody else gets to run.

`GET /trace` arrived with item 11 and is deliberately **not** guarded. It is the read side
of the one stream (§8): a cold browser has to be able to watch an incident without a token,
which is item 11's whole `verify:` line, and a read spends nothing -- which is the entire
reason `/trigger` is guarded and this is not. What makes it safe to serve is §8.1's
redaction rule: span attributes carry identifiers, hashes, enums and numbers, never content,
and `tests/test_telemetry_schema.py` walks every shape enforcing it. `THREAT_MODEL.md`
records what that publishes.

`GET /belief/{entity}` arrived with item 17 and is the **first route here that reads
Firestore**, which is a real departure and not a convenience. §8.2's belief inspector renders
evidence, the arithmetic behind a computed confidence, a supersession chain and a decay
clock -- all of it *content*, and §8.1 keeps content off spans on purpose, so the one stream
structurally cannot serve it. It is unauthenticated for the same reason `/trace` is: a read
spends nothing. `docs/adr/ADR-021` records the departure; `THREAT_MODEL.md` records what it
publishes.

`GET /registry` arrived with item 28 and is the second Firestore reader, for the same reason
the first one exists: §8.2's registry panel renders standing and the `rejection_window` that
earned it, and both are stored state rather than anything the span buffer can be trusted to
still hold. It reads at request time and caches nothing -- §1.1 property 4 is the whole point
of the surface, since what it exists to show is a standing that changed a second ago.
`public_key` is not served: the panel has no use for it and the route is public.
"""

from __future__ import annotations

import asyncio
import hmac
import os
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from dataclasses import asdict
from datetime import UTC, datetime
from importlib.metadata import version
from pathlib import Path
from typing import Any

from fastapi import FastAPI, Header, HTTPException
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field

from provenance import beliefs, incident, policy, registry, telemetry
from provenance.telemetry import TriggerSignal

TRIGGER_TOKEN_ENV = "PROVENANCE_TRIGGER_TOKEN"

_SHELL = Path(__file__).parent / "web" / "index.html"
_VERSION = version("provenance")

# configure_tracing() returns False without GOOGLE_CLOUD_PROJECT, so tests and local runs
# need no credentials. /health reports it: on Cloud Run a False here means the one trace
# stream is not wired, which is a deployment fault worth seeing before Phase 3 needs it.
_tracing = False


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    global _tracing
    _tracing = telemetry.configure_tracing()
    yield


app = FastAPI(title="Provenance", version=_VERSION, lifespan=lifespan)


# /health, not /healthz: the Cloud Run frontend swallows /healthz and answers it with its
# own 404 before the request ever reaches the container (verified on this service, item 3).
@app.get("/health")
async def health() -> dict[str, Any]:
    return {"service": "provenance", "status": "ok", "version": _VERSION, "tracing": _tracing}


@app.get("/")
async def shell() -> FileResponse:
    return FileResponse(_SHELL, media_type="text/html")


@app.get("/trace")
async def spans() -> list[dict[str, Any]]:
    """The one stream, live (item 11). Unauthenticated on purpose -- see the module docstring."""
    return telemetry.BUFFER.snapshot()


@app.get("/belief/{entity}")
async def belief(entity: str) -> dict[str, Any]:
    """§8.2's belief inspector, read side (item 17). Unauthenticated, like `/trace`.

    Serves the whole chain rather than the version in force: §3.2's history block is a *view*
    over versions that already exist, and `beliefs.history()` is the read that produces it,
    `superseded_by` derived rather than stored. The evidence every version cites comes back
    beside it, keyed by id, because a citation the caller cannot resolve is a belief that
    cannot show its work.

    `current.breakdown` is §4.3 recomputed **as of now** against the stored number committed
    at `committed_at`; the two disagree by exactly the decay between them, and that gap is
    the decay clock doing something rather than being a date on a document. Both are served
    so neither has to be inferred. The arithmetic comes from `policy.contributions()` and
    from nowhere else.
    """
    belief_id = beliefs.belief_id_for(entity)
    try:
        versions = await beliefs.history(belief_id)
        cited = {item_id for version in versions for item_id in version.evidence_ids}
        evidence = await beliefs.read_evidence(sorted(cited))
    except beliefs.BeliefNotFound as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    # §7.3: "the store was unreadable" and "the organization believes nothing" must not look
    # alike. A 404 here would tell a caller this entity has no beliefs, which is a claim the
    # service is in no position to make while it cannot read the store.
    except beliefs.BeliefStoreError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    in_force = versions[-1]
    now = datetime.now(UTC)
    by_id = {item.id: item for item in evidence}
    return {
        "belief_id": belief_id,
        "entity": in_force.entity,
        "domain": in_force.domain,
        "scope": in_force.scope,
        "versions": [asdict(version) for version in versions],
        "evidence": {item.id: asdict(item) for item in evidence},
        "current": {
            "version": in_force.version,
            "as_of": now.strftime(beliefs.TIMESTAMP),
            # The half-life comes off the version's own `domain` (item 21), so the number this
            # route recomputes is decayed by the same clock the Policy Engine committed it with.
            "confidence_now": policy.confidence(
                [by_id[i] for i in in_force.evidence_ids], domain=in_force.domain, now=now
            ),
            "breakdown": [
                asdict(row)
                for row in policy.contributions(
                    [by_id[i] for i in in_force.evidence_ids], domain=in_force.domain, now=now
                )
            ],
        },
    }


@app.get("/registry")
async def agents() -> list[dict[str, Any]]:
    """§8.2's registry panel, read side (item 28). Unauthenticated, like `/trace` and `/belief`.

    Read fresh on every request through `registry.get_agent()` -- §1.1 property 4, and the
    reason this route exists at all: a panel showing a cached standing would show the state
    the poisoning arc is about to change rather than the one it just did.
    """
    try:
        records = await asyncio.gather(*(registry.get_agent(a.id) for a in registry.AGENTS))
    # §7.3, and `/belief`'s reasoning applied to standing: "the registry was unreadable" and
    # "every agent is in good standing" must not look alike. An empty or all-GOOD panel during
    # an outage is the one wrong answer this surface is able to give.
    except registry.RegistryError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    return [
        {
            "id": record.id,
            "version": record.version,
            "standing": record.standing,
            "rejection_window": [asdict(entry) for entry in record.rejection_window],
        }
        for record in records
    ]


class TriggerRequest(BaseModel):
    """The wire shape of a trigger. Validated here so a malformed body never wakes the fleet."""

    target: str
    signal: TriggerSignal = "error_rate"
    observed_value: float
    observed_at: str = Field(description="ISO-8601 with a Z suffix.")


def _authorized(token: str | None) -> bool:
    """Constant-time compare, and fail closed when the service was deployed without a token."""
    expected = os.environ.get(TRIGGER_TOKEN_ENV)
    if not expected:
        return False
    return token is not None and hmac.compare_digest(token, expected)


@app.post("/trigger")
async def trigger(
    request: TriggerRequest, x_provenance_token: str | None = Header(default=None)
) -> dict[str, Any]:
    """Wake-on-event (§5.3): one trigger in, one incident out, run to whatever end it reaches."""
    if not _authorized(x_provenance_token):
        raise HTTPException(status_code=403, detail="missing or invalid trigger token")
    result = await incident.run_incident(
        incident.Trigger(
            target=request.target,
            signal=request.signal,
            observed_value=request.observed_value,
            observed_at=request.observed_at,
        )
    )
    return {
        "incident_id": result.incident_id,
        "outcome": result.outcome,
        "malformed_attempts": result.malformed_attempts,
        "refuted_attempts": result.refuted_attempts,
        "action": None if result.action is None else asdict(result.action),
        "decision": None if result.decision is None else asdict(result.decision),
        # Item 10. All three are null unless the path was taken: a held incident executes
        # nothing, and an INCONCLUSIVE verification writes no belief (§7.2).
        "execution": None if result.execution is None else asdict(result.execution),
        "verification": result.verification,
        "belief": None if result.belief is None else asdict(result.belief),
    }
