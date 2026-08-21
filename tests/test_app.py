"""The offline half of ROADMAP item 3: the app answers both routes with no credentials.

The live half is `./scripts/deploy.sh`, which curls the deployed URL. This runs in CI,
where `GOOGLE_CLOUD_PROJECT` is unset, so `configure_tracing()` no-ops and reports False.
"""

from __future__ import annotations

from fastapi.testclient import TestClient

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
