"""ROADMAP item 10's executor, offline: the three fields it writes and the four it refuses on.

The live half is `scripts/verify_incident_one.py`, which rolls the real service back and reads
the real post-state. What is proved here is the half a live run cannot exercise without
forging something: that a `HOLD`, a foreign signature, and a decision about a different target
all stop the write, and that the §9 `rollback_fails` switch is read at execution time rather
than assumed off.

The refusal tests are the whole point of the module. Execution is the only place in this
system where a wrong answer changes stored state, so "would this write have happened anyway?"
has to be answerable with a test rather than with the shape of the call graph.
"""

from __future__ import annotations

import asyncio
from dataclasses import asdict, replace
from typing import Any

import pytest
from cryptography.hazmat.primitives import serialization
from google.api_core.exceptions import ServiceUnavailable
from services.gateway import signing
from test_registry import FakeFirestore

from provenance import action, executor, gateway, risk
from provenance.synthetic import company

TARGET = "inventory-api"


def an_action(**overrides: Any) -> action.Action:
    return replace(
        action.Action(
            action_class="ROLLBACK_CONFIG",
            target=TARGET,
            target_tier="tier2",
            blast_radius="single-service",
            reversible=True,
            evidence_refs=("obs-error-rate",),
            success_predicate="error_rate on inventory-api falls below 0.05 within 10m",
            proposed_by="remediation-planner@v3",
        ),
        **overrides,
    )


def a_decision(
    action_: action.Action,
    *,
    outcome: str = "APPROVE",
    key: Any | None = None,
) -> gateway.Decision:
    """A decision the way the gateway builds one, signed the way the gateway signs one.

    Reaching through `gateway._decision_hash` rather than re-implementing the format is
    deliberate: a test that signed over its own idea of the layout would keep passing if the
    two drifted, which is exactly the drift `verify_decision` exists to catch.
    """
    scored = risk.score(action_)
    subject = f"remediation-planner@v3|{action_.action_class}|{action_.target}"
    payload = gateway._decision_hash(outcome, "risk", "RISK_THRESHOLD", subject, scored)
    signature = signing.sign(key or gateway._signing_key(), payload)
    return gateway.Decision(
        outcome=outcome,  # type: ignore[arg-type]
        stage="risk",
        reason="RISK_THRESHOLD",
        subject=subject,
        score=scored,
        signature=f"ecdsa:{signature.hex()}",
    )


def a_store(
    *,
    rollback_fails: bool = False,
    verification_ambiguous: bool = False,
    spiked: bool = True,
) -> FakeFirestore:
    """The two documents `scripts/inject_fault.py` writes, as it writes them."""
    service = asdict(company.service(TARGET))
    if spiked:
        service |= {"error_rate": 0.38, "healthy": False}
    return FakeFirestore(
        {},
        services={TARGET: service},
        fault_injection={
            TARGET: {
                "target_id": TARGET,
                "error_rate_spike": spiked,
                "rollback_fails": rollback_fails,
                "verification_ambiguous": verification_ambiguous,
            }
        },
    )


# --- the write ----------------------------------------------------------------------------


def test_an_approved_rollback_deploys_the_known_good_version_and_clears_the_fault() -> None:
    """The `verify:` line's first two clauses: rollback executes, error rate drops."""
    store = a_store()
    action_ = an_action()

    result = asyncio.run(executor.execute(action_, a_decision(action_), client=store))
    state = asyncio.run(executor.read_state(TARGET, client=store))

    assert (result.from_version, result.to_version) == ("v42", "v41")
    assert result.rollback_failed is False
    assert state.config_version == "v41"
    assert state.error_rate == company.service(TARGET).error_rate
    assert state.healthy is True


def test_the_version_comes_from_the_entity_model_not_from_the_action() -> None:
    """§3.1 has no `params` field so that this is true (ADR-011).

    The Action carries eight fields and none of them is a version; the only way `v41` can
    reach the store is the entity model. An Action mentioning a version in its predicate --
    which a real Planner will do -- changes nothing about what is deployed.
    """
    store = a_store()
    action_ = an_action(success_predicate="roll back to v13 and error_rate drops below 0.05")

    result = asyncio.run(executor.execute(action_, a_decision(action_), client=store))

    assert result.to_version == company.service(TARGET).known_good_version == "v41"
    assert store.collections["services"][TARGET]["current_config_version"] == "v41"


def test_a_service_with_no_deploy_history_cannot_be_rolled_back() -> None:
    """`pricing-api` has `known_good_version=None`. Raising beats writing `None` as a version."""
    store = FakeFirestore(
        {},
        services={"pricing-api": asdict(company.service("pricing-api"))},
        fault_injection={"pricing-api": {"rollback_fails": False}},
    )
    action_ = an_action(target="pricing-api")
    with pytest.raises(executor.ExecutionError, match="known-good"):
        asyncio.run(executor.execute(action_, a_decision(action_), client=store))


# --- the §9 switch, read at execution time -------------------------------------------------


def test_the_rollback_fails_switch_deploys_the_version_but_leaves_the_rate_spiked() -> None:
    """Item 19's REFUTED path needs a rollback that genuinely does not help (§9).

    The switch is read from Firestore inside `execute()`, not from deploy config and not at
    boot, so it can be flipped mid-take. The version still moves: a rollback that silently
    skipped its own write would make the refutation about the executor rather than about the
    remediation.
    """
    store = a_store(rollback_fails=True)
    action_ = an_action()

    result = asyncio.run(executor.execute(action_, a_decision(action_), client=store))
    state = asyncio.run(executor.read_state(TARGET, client=store))

    assert result.rollback_failed is True
    assert state.config_version == "v41"
    assert state.error_rate == 0.38
    assert state.healthy is False


def test_the_ambiguity_switch_rides_out_on_the_result_and_changes_nothing_here() -> None:
    """Item 19's third switch. The executor reports it; the control loop is what acts on it.

    Read here rather than in the graph node because it lives in the document `execute()`
    already fetches -- but it must not change what this module writes, or the INCONCLUSIVE
    beat would be a fact about a half-done rollback rather than about an unverified one.
    """
    store = a_store(verification_ambiguous=True)
    action_ = an_action()

    result = asyncio.run(executor.execute(action_, a_decision(action_), client=store))
    state = asyncio.run(executor.read_state(TARGET, client=store))

    assert result.verification_ambiguous is True
    assert result.rollback_failed is False
    # The rollback is untouched: v41 deployed, rate back to nominal, service healthy.
    assert state.config_version == "v41"
    assert state.error_rate == company.service(TARGET).error_rate
    assert state.healthy is True


# --- the refusals -------------------------------------------------------------------------


def test_a_held_decision_does_not_execute() -> None:
    """§2.1 stage 7: a HOLD waits for a human. Nothing about it is an authorization."""
    store = a_store()
    action_ = an_action()
    with pytest.raises(executor.ExecutionError, match="not an approval"):
        asyncio.run(executor.execute(action_, a_decision(action_, outcome="HOLD"), client=store))
    assert store.collections["services"][TARGET]["current_config_version"] == "v42"


def test_a_decision_signed_by_another_key_does_not_execute() -> None:
    """The signature is the only thing distinguishing a Decision from a dataclass someone made."""
    store = a_store()
    action_ = an_action()
    forged = a_decision(action_, key=signing.generate_private_key())
    with pytest.raises(executor.ExecutionError, match="does not verify"):
        asyncio.run(executor.execute(action_, forged, client=store))
    assert store.collections["services"][TARGET]["current_config_version"] == "v42"


def test_a_decision_about_another_target_does_not_execute() -> None:
    """`subject` is inside the signature (item 7), so an APPROVE cannot be carried across.

    Without this check the gateway's whole risk table is bypassable: get one cheap rollback
    approved, then present its signed APPROVE beside whatever action you wanted.
    """
    store = a_store()
    approved = an_action(target="checkout-api", success_predicate="checkout recovers")
    with pytest.raises(executor.ExecutionError, match="authorizes"):
        asyncio.run(executor.execute(an_action(), a_decision(approved), client=store))
    assert store.collections["services"][TARGET]["current_config_version"] == "v42"


def test_an_unreachable_store_raises_rather_than_reporting_a_rollback() -> None:
    """§7.3 fail-closed: an execution that did not happen must not be reported as one."""
    store = a_store()
    store.error = ServiceUnavailable("firestore is down")
    action_ = an_action()
    with pytest.raises(executor.ExecutionError):
        asyncio.run(executor.execute(action_, a_decision(action_), client=store))


def test_read_state_is_a_fresh_read_not_an_echo_of_the_write() -> None:
    """The Verification Agent judges what the store says, not what the executor meant.

    Mutating the document behind the executor's back and re-reading is the offline twin of
    the live script's post-state read: if `read_state` returned a cached copy of the write
    payload, the number below would be the one we wrote.
    """
    store = a_store()
    action_ = an_action()
    asyncio.run(executor.execute(action_, a_decision(action_), client=store))
    store.collections["services"][TARGET]["error_rate"] = 0.22

    assert asyncio.run(executor.read_state(TARGET, client=store)).error_rate == 0.22


def test_nothing_here_returns_an_optional() -> None:
    """The same reflection guard items 5 and 6 use: a forgotten `if result:` fails open."""
    for name in ("execute", "read_state"):
        annotation = getattr(executor, name).__annotations__["return"]
        assert "None" not in str(annotation), f"{name} may return an optional"


def test_the_gateway_public_key_is_a_real_pem() -> None:
    """`_check_authorization` loads this on every execution; a malformed one would deny all."""
    serialization.load_pem_public_key(gateway.public_key_pem().encode())
