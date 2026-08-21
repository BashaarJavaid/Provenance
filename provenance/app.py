"""The skeleton service: a health endpoint and the UI shell, deployed on day one.

`ARCHITECTURE.md` §11 stands Cloud Run up in Phase 1 "not at the end" because the trace
UI (item 11), the approval queue (item 30), and the cold-visitor test (item 36) all
assume a live URL to build on. This module is that URL and nothing more.

Deliberately absent: any action endpoint and any auth. The gateway is a *pipeline* (§2.1),
not an endpoint, and the typed Action it carries does not exist until item 6 — an endpoint
stub now would be a request shape invented ahead of its object. `provenance/registry.py`
(item 5) does read Firestore, but from the request path, not from here: no route in this
module touches the database, and the registry panel §8.2 describes is item 11's.
ADK routes and delegates; it does not serve this app (`docs/adr/ADR-007`, ADR-008).
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from importlib.metadata import version
from pathlib import Path
from typing import Any

from fastapi import FastAPI
from fastapi.responses import FileResponse

from provenance import telemetry

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
