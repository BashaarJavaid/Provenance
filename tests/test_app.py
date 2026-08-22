"""The offline half of ROADMAP item 3: the app answers both routes with no credentials.

The live half is `./scripts/deploy.sh`, which curls the deployed URL. This runs in CI,
where `GOOGLE_CLOUD_PROJECT` is unset, so `configure_tracing()` no-ops and reports False.
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from provenance import app as app_module
from provenance import incident
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
