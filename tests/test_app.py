"""The offline half of ROADMAP items 3 and 11: the app answers its routes with no credentials.

The live half is `./scripts/deploy.sh`, which curls the deployed URL, plus item 11's
`/trace` assertions in `scripts/verify_incident_one.py`. This runs in CI, where
`GOOGLE_CLOUD_PROJECT` is unset, so `configure_tracing()` wires no Cloud Trace export and
reports False — while the in-process span buffer works anyway, which is what lets these
tests exercise `/trace` at all.
"""

from __future__ import annotations

from collections.abc import Iterator

import pytest
from fastapi.testclient import TestClient

from provenance import app as app_module
from provenance import incident, telemetry
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
