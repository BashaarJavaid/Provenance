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

`GET /approvals` and `POST /approvals/{id}` arrived with item 30 and are the **first route
pair here that writes**, which ADR-008 and ADR-015 both named as the honest test of "no
framework yet" -- answered at item 31, and the answer was still no (`docs/adr/ADR-033`). The read is unauthenticated for the reason the other three reads are -- item
36's cold judge has to be able to see what the fleet is holding without a token. The write
reuses `/trigger`'s guard and its secret rather than introducing a second: a resume runs the
Verification Agent, so it spends model tokens against the same fixed credit, which is the
entire argument that guarded `/trigger` in the first place, and somebody who can wake the
fleet can already answer what it holds. Nothing here decides anything -- `gateway.resolve()`
does, and it re-validates and re-scores the parked proposal rather than trusting this route
(`docs/adr/ADR-032`).

There is no route for the Staleness Sweeper (item 29) and that is deliberate. §5.11 asks for a
long-running process, so it is one — an `asyncio` task started by the lifespan below — and a
`POST /sweep` would have made it a cron with a public surface to guard. What drives a sweep on
demand, for a script or a demo beat, is `sweeper.sweep()` called directly.

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
import json
import os
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from dataclasses import asdict
from datetime import UTC, datetime
from importlib.metadata import version
from pathlib import Path
from typing import Any, Literal, cast

from fastapi import FastAPI, Header, HTTPException
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field

from provenance import (
    action,
    approvals,
    beliefs,
    executor,
    incident,
    policy,
    registry,
    risk,
    sweeper,
    telemetry,
)
from provenance.telemetry import TriggerSignal

TRIGGER_TOKEN_ENV = "PROVENANCE_TRIGGER_TOKEN"

_SHELL = Path(__file__).parent / "web" / "index.html"
# Item 32's A/B, measured offline and committed. It ships inside the package rather than
# beside its raw runs in `docs/` because the Dockerfile copies `provenance/` and nothing else.
_COUNTERFACTUAL = Path(__file__).parent / "web" / "counterfactual.json"
_VERSION = version("provenance")

# configure_tracing() returns False without GOOGLE_CLOUD_PROJECT, so tests and local runs
# need no credentials. /health reports it: on Cloud Run a False here means the one trace
# stream is not wired, which is a deployment fault worth seeing before Phase 3 needs it.
_tracing = False


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    """Tracing, and item 29's Sweeper — the one thing here that runs when nobody asked it to."""
    global _tracing
    _tracing = telemetry.configure_tracing()
    # §5.11's long-running async process, and one of the two the track's runtime requirement
    # asks for. It lives here rather than in its own service because ADR-008 put everything in
    # one, and it lives in the lifespan rather than a scheduler because a cron is not the thing
    # §5.11 describes. What it costs is stated rather than hidden: the service is deployed at
    # `--min-instances=0`, so the loop consumes expiry while an instance is warm and not on a
    # calendar. `docs/adr/ADR-031` §3.
    task = asyncio.create_task(sweeper.run_forever())
    try:
        yield
    finally:
        await sweeper.cancel(task)


app = FastAPI(title="Provenance", version=_VERSION, lifespan=lifespan)


# /health, not /healthz: the Cloud Run frontend swallows /healthz and answers it with its
# own 404 before the request ever reaches the container (verified on this service, item 3).
@app.get("/health")
async def health() -> dict[str, Any]:
    return {"service": "provenance", "status": "ok", "version": _VERSION, "tracing": _tracing}


@app.get("/")
async def shell() -> FileResponse:
    # `no-store`, because the shell carries the renderers inline: a browser that cached it
    # before a redeploy runs the *old* JavaScript against the new routes (item 31's live
    # finding — the fetches already pass `cache: "no-store"`, but the page itself did not).
    return FileResponse(_SHELL, media_type="text/html", headers={"Cache-Control": "no-store"})


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


@app.get("/counterfactual")
async def counterfactual() -> dict[str, Any]:
    """§8.2's sixth surface, read side (item 32). Unauthenticated, like the other four reads.

    A committed measurement, not a live one. The A/B is twelve real incidents against the real
    fixture; a route that ran them on request would be a button that spends the credit ceiling
    `CLAUDE.md` exists to protect, and would answer a different number every time -- which is
    not what "the A/B table is reproducible from the committed run artifacts" means.

    So this reads a file, and `scripts/verify_counterfactual.py` is what keeps that file
    honest: it re-derives this table from the per-run artifacts in `docs/counterfactual/` and
    refuses if the two disagree. The panel and the report are renderings of the same evidence,
    which is `ADR-021`'s rule applied to a measurement instead of a belief.
    """
    return cast(dict[str, Any], json.loads(_COUNTERFACTUAL.read_text()))


# §2.1's two hold reasons, keyed by the standing that produces each. `SUSPENDED` is absent on
# purpose rather than mapped to a third string: a suspended agent's parked action is not held
# any more, it is refused, and `.get()` returning `None` is the card being told so. Item 28's
# `_LEARNS_FROM` shape -- the rule is the dict, not a branch.
_HOLD_REASON = {"GOOD": "RISK_THRESHOLD", "DEGRADED": "STANDING_DEGRADED"}


async def _derived(record: approvals.Approval) -> dict[str, Any]:
    """§4.2 recomputed and §2.1's hold reason re-derived, in `gateway._re_decide()`'s order.

    Neither is stored on the park (`ADR-032` reason 3 keeps the record an *input*, since
    `_signing_key()` is per process), and neither could honestly be: a park is exactly the
    window in which standing moves, so a stored reason would be a stale one. The card is
    therefore told what a resume would decide *now*.

    `action.validate()` consults its authority in process, so the only cost here is the one
    registry read -- at request time and cached nowhere, §1.1 property 4.
    """
    try:
        validated = action.validate(record.proposal)
        # The *proposing* agent, not `routed_to`. They are routinely different -- the domain
        # agent reasons, the Planner proposes -- and standing is checked against whoever the
        # decision subject names, which is what `gateway._re_decide()` reads. Getting this
        # from `routed_to` reports the wrong agent's standing on exactly item 28's beat: a
        # DEGRADED Planner's score-2 rollback would render as `RISK_THRESHOLD` over a 2.
        agent = await registry.get_agent(validated.proposed_by.split("@")[0])
    # A proposal that no longer validates never reaches the risk table (item 30's live
    # finding: understating a tier is `SCHEMA_INVALID`, not a lower score), and an agent that
    # is gone cannot have its standing read. Both render as "not scored", which is the shape
    # the ledger panel already uses for a decision denied before §4.2.
    except (action.ActionError, registry.AgentNotRegistered):
        return {"risk": None, "hold_reason": None, "executable": False}
    return {
        "risk": asdict(risk.score(validated)),
        "hold_reason": _HOLD_REASON.get(agent.standing),
        # Whether anything downstream could carry this out if the answer were "approve".
        # `DISABLE_COMPLIANCE_CHECKS` is scored 11 and has no executor on purpose (`ADR-003`),
        # so the card must not offer a button whose answer cannot be honoured. It belongs here
        # rather than in the browser for `risk`'s reason: it is a fact about the backend, not
        # English for an enum value, and the browser computes nothing (`ADR-033`).
        "executable": validated.action_class in executor.EXECUTABLE,
    }


@app.get("/approvals")
async def approval_queue() -> list[dict[str, Any]]:
    """§2.1 stage 7's queue, read side (item 30). Unauthenticated, like the other three reads.

    Serves the parked records whole -- the proposal, the subject and the held signature
    included -- because item 31's approval card renders from this and §8.1 keeps the content
    it needs off spans, exactly as `/belief` does. Nothing here is a secret: it is a
    description of an action the fleet has *not* taken and may not take without an answer.

    **Item 31 widened it by derived keys** -- `risk`, `hold_reason` and `executable` -- beside the
    stored fields rather than nesting them, so every reader written before this one still
    parses -- the discipline `approver` took on the ledger. The card needs the §4.2 arithmetic
    component by component and the sentence "held *despite* scoring 2"; the record carries
    neither, the span stream cannot carry them across the restart the park exists to survive,
    and a browser recomputing the risk table would be a second implementation of it. So the
    route computes both, from the one implementation of each (`docs/adr/ADR-033`).
    """
    try:
        parked = await approvals.pending()
        return [asdict(record) | await _derived(record) for record in parked]
    # §7.3, and `/registry`'s reasoning applied to the queue: "the queue was unreadable" and
    # "there is nothing waiting" must not look alike. An empty panel during an outage would
    # tell a human that nothing needs them. A registry outage fails the same way and for the
    # same reason: a card that renders a hold without saying why it is held is the one wrong
    # answer this surface can give.
    except (approvals.ApprovalError, registry.RegistryError) as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc


class ApprovalRequest(BaseModel):
    """The wire shape of a verdict. Two fields, and neither of them is a number.

    `verdict` is a closed pair, so a body that means anything else is a 422 rather than a
    default -- and the default that would otherwise apply is the dangerous one.
    """

    verdict: Literal["approve", "deny"]
    approver: str


@app.post("/approvals/{approval_id}")
async def approve(
    approval_id: str,
    request: ApprovalRequest,
    x_provenance_token: str | None = Header(default=None),
) -> dict[str, Any]:
    """§2.1 stage 7 (item 30): a human answers, and the incident resumes on the other side.

    The only route in this module that can end in a state-mutating action, and it reaches one
    the same way `/trigger` does -- through the control loop, which reaches the gateway, which
    is still the only path (§1.1 property 1). It authorizes nothing itself.
    """
    if not _authorized(x_provenance_token):
        raise HTTPException(status_code=403, detail="missing or invalid trigger token")
    try:
        result = await incident.resume(
            approval_id, verdict=request.verdict, approver=request.approver
        )
    except approvals.ApprovalNotFound as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    # An already-answered park and a malformed approver are both the caller's problem and
    # neither is a server fault: a 409 is what says "this was decided", so a retried POST reads
    # as the no-op it is rather than as a failure worth retrying again.
    except approvals.ApprovalNotPending as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    except approvals.ApprovalError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return {
        "incident_id": result.incident_id,
        "approval_id": result.approval_id,
        "outcome": result.outcome,
        "decision": None if result.decision is None else asdict(result.decision),
        "action": None if result.action is None else asdict(result.action),
        # All three are null on a denial, which is the point of a denial.
        "execution": None if result.execution is None else asdict(result.execution),
        "verification": result.verification,
        "belief": None if result.belief is None else asdict(result.belief),
    }


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
        # Item 30: null unless the incident was held. A caller that gets `HELD` has the id it
        # needs to answer, rather than having to search `GET /approvals` for its own incident --
        # which is the difference between a documented flow and a scavenger hunt (item 36).
        "approval_id": result.approval_id,
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
