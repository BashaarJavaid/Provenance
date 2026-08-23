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
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from fastapi.testclient import TestClient
from test_registry import FakeFirestore

from provenance import app as app_module
from provenance import beliefs, incident, policy, telemetry
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
        confidence=policy.confidence(items, now=at),
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
