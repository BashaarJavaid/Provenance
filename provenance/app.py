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
against a fixed credit; an open endpoint is a loop somebody else gets to run. The registry
panel §8.2 describes is still item 11's, and no route here reads Firestore directly.
"""

from __future__ import annotations

import hmac
import os
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from dataclasses import asdict
from importlib.metadata import version
from pathlib import Path
from typing import Any

from fastapi import FastAPI, Header, HTTPException
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field

from provenance import incident, telemetry
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
        "action": None if result.action is None else asdict(result.action),
        "decision": None if result.decision is None else asdict(result.decision),
        # Item 10. All three are null unless the path was taken: a held incident executes
        # nothing, and an INCONCLUSIVE verification writes no belief (§7.2).
        "execution": None if result.execution is None else asdict(result.execution),
        "verification": result.verification,
        "belief": None if result.belief is None else asdict(result.belief),
    }
