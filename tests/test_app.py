"""The offline half of ROADMAP items 3 and 11: the app answers its routes with no credentials.

The live half is `./scripts/deploy.sh`, which curls the deployed URL, plus item 11's
`/trace` assertions in `scripts/verify_incident_one.py`. This runs in CI, where
`GOOGLE_CLOUD_PROJECT` is unset, so `configure_tracing()` wires no Cloud Trace export and
reports False — while the in-process span buffer works anyway, which is what lets these
tests exercise `/trace` at all.
"""

from __future__ import annotations

import asyncio
from collections.abc import Iterator
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from fastapi.testclient import TestClient
from google.api_core.exceptions import ServiceUnavailable
from test_registry import FakeFirestore

from provenance import app as app_module
from provenance import (
    approvals,
    beliefs,
    incident,
    policy,
    registry,
    sweeper,
    telemetry,
)
from provenance.app import app


def test_health_reports_the_service_and_its_tracing_state() -> None:
    with TestClient(app) as client:
        response = client.get("/health")
    assert response.status_code == 200
    body = response.json()
    assert body["service"] == "provenance"
    assert body["status"] == "ok"
    assert body["version"]
    # No GOOGLE_CLOUD_PROJECT in CI: emitting stays safe, export is off.
    assert body["tracing"] is False


def test_the_lifespan_runs_the_sweeper_and_stops_it(monkeypatch: pytest.MonkeyPatch) -> None:
    """Item 29's loop is §5.11's async process, so it has to actually start — and stop.

    A task left running past shutdown is a Cloud Run instance still reading Firestore while
    the service is being torn down. What the lifespan owns is exactly these two moments; the
    ticking itself is `tests/test_sweeper.py`.
    """
    state: list[str] = []

    async def forever() -> None:
        state.append("started")
        try:
            await asyncio.Event().wait()
        except asyncio.CancelledError:
            state.append("cancelled")
            raise

    monkeypatch.setattr(sweeper, "run_forever", forever)
    with TestClient(app) as client:
        client.get("/health")
        assert state == ["started"]
    assert state == ["started", "cancelled"]


def test_root_serves_the_shell_with_all_six_surfaces() -> None:
    with TestClient(app) as client:
        response = client.get("/")
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/html")
    # The six ARCHITECTURE §8.2 surfaces, asserted as literal strings so renaming one in
    # the shell fails the build rather than silently dropping a region.
    for surface in (
        "Live fleet view",
        "Gateway ledger",
        "Belief inspector",
        "Registry panel",
        "Approval card",
        "Counterfactual panel",
    ):
        assert surface in response.text


# --- GET /trace (item 11) -----------------------------------------------------------------


@pytest.fixture
def buffer() -> Iterator[None]:
    telemetry.BUFFER.clear()
    yield
    telemetry.BUFFER.clear()


def test_trace_is_readable_without_a_token(buffer: None) -> None:
    """Item 11's verify line is a *cold* browser: no header, no credentials, no console.

    The guard on /trigger exists because a trigger spends model tokens. A read spends
    nothing, and §8.1 keeps content out of the stream, so this one is open by design.
    """
    with TestClient(app) as client:
        assert client.get("/trace").json() == []
        with telemetry.incident(
            incident_id="inc-cold", trigger_target="inventory-api", trigger_signal="error_rate"
        ) as rec:
            running = client.get("/trace")
            rec.set_outcome(outcome="RESOLVED", malformed_attempts=0, predicate_id="abc123")
        done = client.get("/trace")

    assert running.status_code == 200
    assert running.json()[0]["running"] is True
    assert running.json()[0]["attrs"]["provenance.incident.id"] == "inc-cold"

    assert done.status_code == 200
    body = done.json()
    assert len(body) == 1
    assert body[0]["name"] == "provenance.incident"
    assert body[0]["running"] is False
    assert body[0]["status"] == "OK"
    assert body[0]["attrs"]["provenance.incident.outcome"] == "RESOLVED"
    assert body[0]["trace_id"] and body[0]["span_id"]
    assert body[0]["parent_id"] is None


def test_trace_never_serves_content(buffer: None) -> None:
    """§8.1's redaction rule, checked on the bytes that actually leave the process."""
    forbidden = ("prompt", "rationale", "payload", "text", "content", "message", "body")
    with TestClient(app) as client:
        with telemetry.reasoning_chain(
            agent_id="sre-infra-agent",
            agent_version="v1",
            model="gemini-2.5-pro",
            step="diagnose",
            recall_belief_ids=(),
        ) as rec:
            rec.set_result(
                hypotheses_considered=3,
                selected_hypothesis="config_regression",
                input_tokens=10,
                output_tokens=20,
            )
        body = client.get("/trace").json()

    assert body
    for span in body:
        for key in span["attrs"]:
            assert not any(part in key for part in forbidden), key


# --- POST /trigger (item 9) ---------------------------------------------------------------

A_TRIGGER = {
    "target": "inventory-api",
    "signal": "error_rate",
    "observed_value": 0.38,
    "observed_at": "2026-08-21T14:06:00Z",
}


def test_trigger_is_refused_without_the_shared_secret(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(app_module.TRIGGER_TOKEN_ENV, "s3cret")
    with TestClient(app) as client:
        assert client.post("/trigger", json=A_TRIGGER).status_code == 403
        assert (
            client.post("/trigger", json=A_TRIGGER, headers={"X-Provenance-Token": "wrong"})
        ).status_code == 403


def test_trigger_fails_closed_when_the_service_was_deployed_without_a_token(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """An unset token must lock the door, not remove it (§7.3)."""
    monkeypatch.delenv(app_module.TRIGGER_TOKEN_ENV, raising=False)
    with TestClient(app) as client:
        response = client.post(
            "/trigger", json=A_TRIGGER, headers={"X-Provenance-Token": "anything"}
        )
    assert response.status_code == 403


def test_a_malformed_trigger_body_never_wakes_the_fleet(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(app_module.TRIGGER_TOKEN_ENV, "s3cret")
    called = False

    async def fail(*args: object, **kwargs: object) -> None:
        nonlocal called
        called = True

    monkeypatch.setattr(app_module.incident, "run_incident", fail)
    with TestClient(app) as client:
        response = client.post(
            "/trigger",
            json={"target": "inventory-api", "signal": "cosmic_rays", "observed_value": 0.38},
            headers={"X-Provenance-Token": "s3cret"},
        )
    assert response.status_code == 422
    assert not called


def test_an_authorized_trigger_returns_what_the_gateway_decided(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The route's own contract: it reports the decision, it does not make one."""
    monkeypatch.setenv(app_module.TRIGGER_TOKEN_ENV, "s3cret")
    seen: dict[str, object] = {}

    async def fake_run(trigger: object, **kwargs: object) -> incident.IncidentResult:
        seen["trigger"] = trigger
        return incident.IncidentResult(
            incident_id="inc-abc123",
            outcome="AUTHORIZED",
            decision=None,
            action=None,
            malformed_attempts=0,
        )

    monkeypatch.setattr(app_module.incident, "run_incident", fake_run)
    with TestClient(app) as client:
        response = client.post("/trigger", json=A_TRIGGER, headers={"X-Provenance-Token": "s3cret"})
    assert response.status_code == 200
    assert response.json()["outcome"] == "AUTHORIZED"
    assert response.json()["incident_id"] == "inc-abc123"
    assert seen["trigger"] == incident.Trigger(
        target="inventory-api",
        signal="error_rate",
        observed_value=0.38,
        observed_at="2026-08-21T14:06:00Z",
    )


# --- GET /belief/{entity} (item 17) --------------------------------------------------------

# The seeded SUP-042 chain in miniature: two versions, a flip, three evidence items across
# three source classes. Committed times eight days apart, which is what makes v1's items
# decayed by the time v2 is in force -- and therefore what makes `confidence_now` differ
# from the number stored on the version.
_V1_AT = datetime(2026, 8, 15, 9, 0, 0, tzinfo=UTC)
_V2_AT = _V1_AT + timedelta(days=8)


def _evidence(source_class: str, source_id: str, at: datetime) -> beliefs.Evidence:
    stamp = at.strftime(beliefs.TIMESTAMP)
    return beliefs.Evidence(
        id=beliefs.evidence_id(source_id, stamp),
        source_id=source_id,
        source_class=source_class,  # type: ignore[arg-type]
        observed_at=stamp,
        ingested_at=stamp,
        payload_hash=beliefs.payload_hash({"source_id": source_id}),
        verifiable_by=f"re-read {source_id}",
    )


_CONTRACT = _evidence("contractual_record", "contract:CTR-2024-0042", _V1_AT)
_INFERENCE = _evidence("agent_inference", "agent:supply-chain-agent", _V1_AT)
_AUDIT = _evidence("third_party_audit", "compliance-feed:SUP-042", _V2_AT)


def _version(n: int, status: str, at: datetime, *evidence: beliefs.Evidence) -> Any:
    items = list(evidence)
    return beliefs.BeliefVersion(
        belief_id="belief-SUP-042",
        version=n,
        scope="ENTITY",
        domain="supply-chain",
        entity="SUP-042",
        status=status,
        confidence=policy.confidence(items, domain="supply-chain", now=at),
        threshold=0.50 if n == 1 else 0.70,
        evidence_ids=tuple(item.id for item in items),
        authority="supply-chain-agent@v1",
        committed_at=at.strftime(beliefs.TIMESTAMP),
        committed_by="memory-policy-engine",
        signature="ecdsa:deadbeef",
        supersedes=None if n == 1 else n - 1,
        half_life_days=30.0,
        expires_at=(at + timedelta(days=30)).strftime(beliefs.TIMESTAMP),
    )


@pytest.fixture
def store(monkeypatch: pytest.MonkeyPatch) -> FakeFirestore:
    """A fake Firestore holding the two-version SUP-042 chain, wired in as the default client."""
    fake = FakeFirestore({})
    asyncio.run(
        beliefs.append(_version(1, "FLAGGED", _V1_AT, _CONTRACT, _INFERENCE), (), client=fake)
    )
    asyncio.run(
        beliefs.append(
            _version(2, "AT_RISK", _V2_AT, _CONTRACT, _INFERENCE, _AUDIT),
            (_CONTRACT, _INFERENCE, _AUDIT),
            client=fake,
        )
    )
    monkeypatch.setattr(beliefs, "_default_client", lambda: fake)
    return fake


def test_the_inspector_is_readable_without_a_token(store: FakeFirestore) -> None:
    """Item 17's surface is item 36's cold judge again: a read spends nothing, so it is open.

    The guard on /trigger exists because a trigger spends model tokens against a fixed
    credit. Nothing here can be made to spend anything, and the company is synthetic.
    """
    with TestClient(app) as client:
        response = client.get("/belief/SUP-042")
    assert response.status_code == 200
    body = response.json()
    assert body["belief_id"] == "belief-SUP-042"
    assert body["entity"] == "SUP-042"
    assert body["domain"] == "supply-chain"
    assert body["scope"] == "ENTITY"


def test_the_breakdown_reproduces_the_number_it_explains(store: FakeFirestore) -> None:
    """The item's `verify:` line: "the inspector shows the computed confidence breakdown".

    A breakdown that does not multiply back to the confidence beside it is decoration. This
    is `telemetry.set_risk()`'s rule for the risk components, applied to §4.3's product.
    """
    with TestClient(app) as client:
        current = client.get("/belief/SUP-042").json()["current"]
    product = 1.0
    for row in current["breakdown"]:
        assert row["weight"] == pytest.approx(row["base"] * 2 ** (-row["age_days"] / 30.0))
        product *= 1 - row["weight"]
    assert 1 - product == pytest.approx(current["confidence_now"])
    # Three distinct source classes back the version in force, and each appears exactly once.
    assert len(current["breakdown"]) == 3
    assert {row["source_class"] for row in current["breakdown"]} == {
        "contractual_record",
        "agent_inference",
        "third_party_audit",
    }


def test_the_chain_comes_back_whole_with_the_backlink_derived(store: FakeFirestore) -> None:
    """§3.2's history block is a view, and this is the route that serves it.

    `superseded_by` is never stored (ADR-016 reason 2) -- v1 carries it here only because
    `beliefs.history()` derived it from v2 existing.
    """
    with TestClient(app) as client:
        body = client.get("/belief/SUP-042").json()
    v1, v2 = body["versions"]
    assert (v1["version"], v1["status"], v1["supersedes"], v1["superseded_by"]) == (
        1,
        "FLAGGED",
        None,
        2,
    )
    assert (v2["version"], v2["status"], v2["supersedes"], v2["superseded_by"]) == (
        2,
        "AT_RISK",
        1,
        None,
    )
    assert v1["confidence"] == pytest.approx(0.575)
    assert v2["confidence"] == pytest.approx(0.7698, abs=0.0005)
    # Every citation resolves: a belief that cannot produce its own provenance is one that lies.
    assert set(body["evidence"]) == set(v1["evidence_ids"]) | set(v2["evidence_ids"])
    assert body["evidence"][_AUDIT.id]["verifiable_by"] == "re-read compliance-feed:SUP-042"


def test_the_decay_clock_is_served_and_has_already_moved(store: FakeFirestore) -> None:
    """§6.5: the stored number is what was true at commit; `confidence_now` is what is true now.

    They differ by exactly the decay between the two, which is the clock doing something
    rather than being a date on a document. The fixture is committed in the past, so the
    gap is real without the test having to wait for it.
    """
    with TestClient(app) as client:
        body = client.get("/belief/SUP-042").json()
    in_force = body["versions"][-1]
    assert in_force["half_life_days"] == 30.0
    assert in_force["on_expiry"] == "REVERIFY"
    assert in_force["expires_at"] > in_force["committed_at"]
    assert body["current"]["confidence_now"] < in_force["confidence"], "it can only weaken"


def test_an_unknown_entity_is_404(store: FakeFirestore) -> None:
    with TestClient(app) as client:
        assert client.get("/belief/nonesuch").status_code == 404


def test_an_unreadable_store_is_503_and_not_404(monkeypatch: pytest.MonkeyPatch) -> None:
    """§7.3, on the read side: "nothing is here" is a claim, and an outage cannot make it.

    A 404 would tell a caller this entity has no beliefs -- which, mid-outage, the service
    has no way of knowing. Item 28's closing shot is "SUP-042 is still AT_RISK"; a route
    that answers 404 when Firestore blinks would show that shot as the poisoning working.
    """

    async def unreadable(*args: object, **kwargs: object) -> None:
        raise beliefs.BeliefStoreUnavailable("firestore unreachable")

    monkeypatch.setattr(beliefs, "history", unreadable)
    with TestClient(app) as client:
        assert client.get("/belief/SUP-042").status_code == 503


# --- the registry panel, item 28 ---------------------------------------------------------


@pytest.fixture
def agents(monkeypatch: pytest.MonkeyPatch) -> FakeFirestore:
    """The four fixture agents as stored records, with the poisoned one already DEGRADED."""
    fake = FakeFirestore(
        {
            agent.id: registry.to_document(
                replace(
                    agent,
                    public_key="-----BEGIN PUBLIC KEY-----\nnot-a-real-key\n-----END PUBLIC KEY-----",
                    standing="DEGRADED" if agent.id == "supply-chain-agent" else agent.standing,
                    rejection_window=(
                        tuple(
                            registry.RejectionEntry(rejected_at=at, reason="FLIP_UNSUPPORTED")
                            for at in (
                                "2026-08-25T10:00:00Z",
                                "2026-08-25T10:01:00Z",
                                "2026-08-25T10:02:00Z",
                            )
                        )
                        if agent.id == "supply-chain-agent"
                        else agent.rejection_window
                    ),
                )
            )
            for agent in registry.AGENTS
        }
    )
    monkeypatch.setattr(registry, "_default_client", lambda: fake)
    return fake


def test_the_registry_panel_is_readable_without_a_token(agents: FakeFirestore) -> None:
    """Item 28's `verify:` line: the DEGRADED transition has to be visible live.

    Open for the same reason `/trace` and `/belief` are -- a read spends nothing, and item
    36's cold judge has no token. What it publishes is standing and the reasons that earned
    it, which is what `THREAT_MODEL.md` records against this route.
    """
    with TestClient(app) as client:
        response = client.get("/registry")
    assert response.status_code == 200
    body = response.json()
    assert [row["id"] for row in body] == [agent.id for agent in registry.AGENTS]
    poisoned = next(row for row in body if row["id"] == "supply-chain-agent")
    assert poisoned["standing"] == "DEGRADED"
    assert [entry["reason"] for entry in poisoned["rejection_window"]] == ["FLIP_UNSUPPORTED"] * 3
    # The contrast is the point: one row flips while the rest hold, which is what makes the
    # transition legible on the panel rather than being a single label nobody can calibrate.
    assert {row["standing"] for row in body if row["id"] != "supply-chain-agent"} == {"GOOD"}


def test_the_registry_panel_never_serves_a_public_key(agents: FakeFirestore) -> None:
    """The record carries one; the panel has no use for it and the route is unauthenticated.

    Not a secret -- it is a *public* key, and item 7 verifies signatures against it. But this
    route exists to render standing, and a field served because it happened to be on the
    record is a field the next reader assumes something depends on.
    """
    with TestClient(app) as client:
        body = client.get("/registry").json()
    assert all("public_key" not in row for row in body)
    assert all(set(row) == {"id", "version", "standing", "rejection_window"} for row in body)


def test_an_unreadable_registry_is_503_and_not_an_all_good_panel(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """§7.3 on the panel: "the registry was unreadable" and "everyone is in good standing"
    must not look alike.

    This is the one wrong answer the surface can give. Item 28's whole beat is a standing
    that *changed*; a route that degrades to an empty or all-GOOD list during an outage
    would render the poisoning as having been repelled at exactly the moment nobody knows.
    """

    async def unreadable(*args: object, **kwargs: object) -> None:
        raise registry.RegistryUnavailable("firestore unreachable")

    monkeypatch.setattr(registry, "get_agent", unreadable)
    with TestClient(app) as client:
        response = client.get("/registry")
    assert response.status_code == 503
    assert response.json() != []


# --- the approval queue, item 30 -----------------------------------------------------------


A_PARKED = approvals.Approval(
    id="appr-3f2b1c",
    incident_id="inc-abc123",
    state="PARKED",
    proposal={"action_class": "ROLLBACK_CONFIG", "target": "inventory-api"},
    subject="remediation-planner@v3|ROLLBACK_CONFIG|inventory-api",
    held_signature="ecdsa:deadbeef",
    entity_ids=("belief-inventory-api",),
    domain="infrastructure",
    routed_to="sre-infra-agent",
    trigger_target="inventory-api",
    trigger_signal="error_rate",
    trigger_observed_value=0.38,
    trace_id="9a0b237f4f576fc4da35e4e76bd0ee03",
    parked_at="2026-08-26T12:00:00Z",
)


@pytest.fixture
def queue(monkeypatch: pytest.MonkeyPatch) -> FakeFirestore:
    fake = FakeFirestore({}, approvals={A_PARKED.id: approvals.to_document(A_PARKED)})
    monkeypatch.setattr(approvals, "_default_client", lambda: fake)
    return fake


def test_the_approval_queue_is_readable_without_a_token(queue: FakeFirestore) -> None:
    """Item 36's cold judge has to see what the fleet is holding before being handed a secret.

    Open for the reason the other three reads are: a read spends nothing, and a parked record
    describes an action the fleet has *not* taken and may not take without an answer.
    """
    with TestClient(app) as client:
        response = client.get("/approvals")
    assert response.status_code == 200
    [record] = response.json()
    assert record["id"] == A_PARKED.id
    assert record["state"] == "PARKED"
    # Item 31's card renders from this, and §8.1 keeps the content it needs off spans.
    assert record["proposal"]["action_class"] == "ROLLBACK_CONFIG"
    assert record["entity_ids"] == ["belief-inventory-api"]


def test_an_unreadable_queue_is_a_503_rather_than_an_empty_one(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """§7.3, and `/registry`'s reasoning: telling a human nothing needs them is the wrong answer."""
    fake = FakeFirestore({}, error=ServiceUnavailable("down"), approvals={})
    monkeypatch.setattr(approvals, "_default_client", lambda: fake)
    with TestClient(app) as client:
        assert client.get("/approvals").status_code == 503


def test_a_verdict_is_refused_without_the_shared_secret(
    monkeypatch: pytest.MonkeyPatch, queue: FakeFirestore
) -> None:
    monkeypatch.setenv(app_module.TRIGGER_TOKEN_ENV, "s3cret")
    body = {"verdict": "approve", "approver": "dana.ruiz"}
    with TestClient(app) as client:
        assert client.post(f"/approvals/{A_PARKED.id}", json=body).status_code == 403
        assert (
            client.post(
                f"/approvals/{A_PARKED.id}", json=body, headers={"X-Provenance-Token": "wrong"}
            )
        ).status_code == 403
    assert queue.collections["approvals"][A_PARKED.id]["state"] == "PARKED"


def test_a_verdict_fails_closed_when_the_service_was_deployed_without_a_token(
    monkeypatch: pytest.MonkeyPatch, queue: FakeFirestore
) -> None:
    monkeypatch.delenv(app_module.TRIGGER_TOKEN_ENV, raising=False)
    with TestClient(app) as client:
        response = client.post(
            f"/approvals/{A_PARKED.id}",
            json={"verdict": "approve", "approver": "dana.ruiz"},
            headers={"X-Provenance-Token": "anything"},
        )
    assert response.status_code == 403


def test_a_verdict_outside_the_closed_pair_never_reaches_the_loop(
    monkeypatch: pytest.MonkeyPatch, queue: FakeFirestore
) -> None:
    """The default that would otherwise apply is the dangerous one, so there is no default."""
    monkeypatch.setenv(app_module.TRIGGER_TOKEN_ENV, "s3cret")
    called = False

    async def fail(*args: object, **kwargs: object) -> None:
        nonlocal called
        called = True

    monkeypatch.setattr(app_module.incident, "resume", fail)
    with TestClient(app) as client:
        response = client.post(
            f"/approvals/{A_PARKED.id}",
            json={"verdict": "maybe", "approver": "dana.ruiz"},
            headers={"X-Provenance-Token": "s3cret"},
        )
    assert response.status_code == 422
    assert not called


def test_an_authorized_verdict_returns_what_the_resumed_leg_did(
    monkeypatch: pytest.MonkeyPatch, queue: FakeFirestore
) -> None:
    """The route's own contract: it reports the resolution, it does not make one."""
    monkeypatch.setenv(app_module.TRIGGER_TOKEN_ENV, "s3cret")
    seen: dict[str, Any] = {}

    async def resumed(approval_id: str, **kwargs: Any) -> incident.IncidentResult:
        seen.update({"approval_id": approval_id, **kwargs})
        return incident.IncidentResult(
            incident_id="inc-abc123",
            outcome="DENIED",
            decision=None,
            action=None,
            malformed_attempts=0,
            approval_id=approval_id,
        )

    monkeypatch.setattr(app_module.incident, "resume", resumed)
    with TestClient(app) as client:
        response = client.post(
            f"/approvals/{A_PARKED.id}",
            json={"verdict": "deny", "approver": "dana.ruiz"},
            headers={"X-Provenance-Token": "s3cret"},
        )
    assert response.status_code == 200
    assert response.json()["outcome"] == "DENIED"
    assert seen == {
        "approval_id": A_PARKED.id,
        "verdict": "deny",
        "approver": "dana.ruiz",
    }


def test_an_absent_approval_is_a_404(monkeypatch: pytest.MonkeyPatch, queue: FakeFirestore) -> None:
    monkeypatch.setenv(app_module.TRIGGER_TOKEN_ENV, "s3cret")
    with TestClient(app) as client:
        response = client.post(
            "/approvals/appr-nothing",
            json={"verdict": "approve", "approver": "dana.ruiz"},
            headers={"X-Provenance-Token": "s3cret"},
        )
    assert response.status_code == 404


def test_an_already_answered_approval_is_a_409(
    monkeypatch: pytest.MonkeyPatch, queue: FakeFirestore
) -> None:
    """A retried POST reads as the no-op it is, not as something worth retrying again."""
    monkeypatch.setenv(app_module.TRIGGER_TOKEN_ENV, "s3cret")
    queue.collections["approvals"][A_PARKED.id]["state"] = "DENIED"
    with TestClient(app) as client:
        response = client.post(
            f"/approvals/{A_PARKED.id}",
            json={"verdict": "approve", "approver": "dana.ruiz"},
            headers={"X-Provenance-Token": "s3cret"},
        )
    assert response.status_code == 409


def test_an_approver_that_is_not_an_identifier_is_a_400(
    monkeypatch: pytest.MonkeyPatch, queue: FakeFirestore
) -> None:
    monkeypatch.setenv(app_module.TRIGGER_TOKEN_ENV, "s3cret")
    with TestClient(app) as client:
        response = client.post(
            f"/approvals/{A_PARKED.id}",
            json={"verdict": "approve", "approver": "not an identifier"},
            headers={"X-Provenance-Token": "s3cret"},
        )
    assert response.status_code == 400
    assert queue.collections["approvals"][A_PARKED.id]["state"] == "PARKED"
