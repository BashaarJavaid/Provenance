"""ROADMAP item 7's `verify:` line, second half: §2.1 end to end, denials included.

`ARCHITECTURE.md` §10's **Gateway** row -- "Test that flips an agent's standing to DEGRADED
mid-run and asserts the *next* proposal is held regardless of risk score; test that a
low-risk action from a SUSPENDED agent is denied" -- is `test_a_standing_flip_between_two_
authorizations_holds_the_second` and `test_a_suspended_agent_is_denied_even_at_risk_2`.
The two worked examples score 2 and 11 here as well as in `tests/test_risk.py`, because
scoring correctly in isolation and scoring correctly through the pipeline are two claims.

The store is `tests/test_registry.py`'s dict fake, reused rather than rebuilt: item 5 wrote
it precisely so a value changing *between two reads* would be visible, which is the shape
the standing-flip test needs.

The live half is `scripts/verify_gateway.py`.
"""

from __future__ import annotations

import asyncio
import inspect
import types
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from typing import Any, Union, get_args, get_origin, get_type_hints

import pytest
from conftest import attach_exporter
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from google.api_core.exceptions import ServiceUnavailable
from opentelemetry.sdk.trace import ReadableSpan
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter
from test_registry import FakeFirestore

from provenance import credentials, gateway, registry, risk

T0 = datetime(2026, 8, 21, 12, 0, 0, tzinfo=UTC)

_EXPORTER = attach_exporter()


@pytest.fixture
def spans() -> Any:
    _EXPORTER.clear()
    yield _EXPORTER
    _EXPORTER.clear()


# --- the world under test -----------------------------------------------------------------

PLANNER_KEY = ec.generate_private_key(ec.SECP256R1())
PLANNER_PEM = (
    PLANNER_KEY.public_key()
    .public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
    .decode()
)


def a_store(**overrides: Any) -> FakeFirestore:
    """The registry as seeded: `remediation-planner`, GOOD, holding §4.2's two action classes."""
    record = registry.Agent(
        id="remediation-planner",
        version="v1",
        public_key=PLANNER_PEM,
        tool_scope=("ROLLBACK_CONFIG", "DISABLE_COMPLIANCE_CHECKS"),
        memory_domains=(),
        standing="GOOD",
        rejection_window=(),
    )
    return FakeFirestore(
        {"remediation-planner": registry.to_document(replace(record, **overrides))}
    )


def a_credential(**overrides: Any) -> credentials.Credential:
    cred = credentials.mint("remediation-planner", "v1", PLANNER_KEY, now=T0)
    return replace(cred, **overrides) if overrides else cred


def a_rollback(**overrides: Any) -> dict[str, Any]:
    """§4.2's first worked example: must score 2 and auto-approve."""
    return {
        "action_class": "ROLLBACK_CONFIG",
        "target": "inventory-api",
        "target_tier": "tier2",
        "blast_radius": "single-service",
        "reversible": True,
        "evidence_refs": ["ev-118"],
        "success_predicate": "error_rate < 0.05 within 10m",
        "proposed_by": "remediation-planner@v1",
    } | overrides


def a_disable(**overrides: Any) -> dict[str, Any]:
    """§4.2's second worked example: must score 11 and hold."""
    return {
        "action_class": "DISABLE_COMPLIANCE_CHECKS",
        "target": "SUP-042",
        "target_tier": "tier1",
        "blast_radius": "org-wide",
        "reversible": False,
        "evidence_refs": ["ev-140"],
        "success_predicate": "compliance_checks_enabled == false",
        "proposed_by": "remediation-planner@v1",
    } | overrides


def authorize(
    proposal: object,
    *,
    store: FakeFirestore | None = None,
    credential: credentials.Credential | None = None,
    now: datetime = T0,
) -> gateway.Decision:
    return asyncio.run(
        gateway.authorize(
            proposal,
            credential if credential is not None else a_credential(),
            now=now,
            client=store if store is not None else a_store(),
        )
    )


def _only(exporter: InMemorySpanExporter) -> ReadableSpan:
    finished = exporter.get_finished_spans()
    assert len(finished) == 1
    return finished[0]


# --- §4.2's two worked examples, through the whole pipeline --------------------------------


def test_the_rollback_worked_example_is_approved_at_risk_2() -> None:
    decision = authorize(a_rollback())
    assert (decision.outcome, decision.stage, decision.reason) == (
        "APPROVE",
        "risk",
        "RISK_THRESHOLD",
    )
    assert decision.score is not None
    assert decision.score.score == 2


def test_the_disable_compliance_worked_example_is_held_at_risk_11() -> None:
    # THREAT_MODEL.md's injection row: "the demo shows both outer layers leaking and the
    # gateway holding at score 11". This is that hold, with no payload anywhere in sight.
    decision = authorize(a_disable())
    assert (decision.outcome, decision.stage, decision.reason) == ("HOLD", "risk", "RISK_THRESHOLD")
    assert decision.score is not None
    assert decision.score.score == 11


# --- §10's Gateway row --------------------------------------------------------------------


def test_a_standing_flip_between_two_authorizations_holds_the_second() -> None:
    # §1.1 #4: "an agent's standing can change mid-run and the next authorization reflects
    # it". One process, one store, one client -- only the stored value moves.
    store = a_store()
    first = authorize(a_rollback(), store=store)
    assert first.outcome == "APPROVE"

    store.docs["remediation-planner"]["standing"] = "DEGRADED"

    second = authorize(a_rollback(), store=store)
    assert (second.outcome, second.stage, second.reason) == (
        "HOLD",
        "registry",
        "STANDING_DEGRADED",
    )
    # §3.4: held "regardless of risk score" -- and the score is still 2, which is the point.
    assert second.score is not None
    assert second.score.score == 2


def test_a_suspended_agent_is_denied_even_at_risk_2() -> None:
    decision = authorize(a_rollback(), store=a_store(standing="SUSPENDED"))
    assert (decision.outcome, decision.stage, decision.reason) == (
        "DENY",
        "registry",
        "STANDING_SUSPENDED",
    )
    # A denial owes the human no arithmetic; §8.1 wants the span to carry none either.
    assert decision.score is None


def test_a_degraded_hold_carries_the_arithmetic_a_suspended_denial_does_not() -> None:
    # Item 31's approval card renders the component-by-component breakdown for everything a
    # human is asked to approve. "Held despite scoring 2" is the sentence item 28's beat needs.
    held = authorize(a_rollback(), store=a_store(standing="DEGRADED"))
    denied = authorize(a_rollback(), store=a_store(standing="SUSPENDED"))
    assert held.score is not None and denied.score is None


# --- stage 1: schema (§2.1, §7.1) -----------------------------------------------------------


@pytest.mark.parametrize(
    "proposal",
    [
        "roll back inventory-api please",  # free-form text
        None,
        {"action_class": "DELETE_DATABASE"},  # fabricated tool, wrong shape
        a_rollback(action_class="DELETE_DATABASE"),  # fabricated tool, right shape
        a_rollback(target="ghost-api"),  # nonexistent target
        a_rollback(reversible=False),  # Planner contradicting the tool registry
        a_rollback(target_tier="tier3"),  # Planner understating the tier
    ],
)
def test_anything_that_is_not_a_valid_typed_action_dies_at_stage_one(proposal: object) -> None:
    decision = authorize(proposal)
    assert (decision.outcome, decision.stage, decision.reason) == (
        "DENY",
        "schema",
        "SCHEMA_INVALID",
    )
    assert decision.score is None


def test_a_schema_denial_never_reaches_the_registry() -> None:
    # §7.1: "before the gateway ever sees it" means before the registry read too. A store
    # that raises on any read proves nothing touched it.
    store = FakeFirestore({}, error=ServiceUnavailable("must not be reached"))
    decision = authorize("free-form text", store=store)
    assert decision.reason == "SCHEMA_INVALID"


# --- stage 2: identity (§2.1) ---------------------------------------------------------------


def test_an_expired_credential_is_denied() -> None:
    decision = authorize(a_rollback(), now=T0 + timedelta(seconds=300))
    assert (decision.outcome, decision.stage, decision.reason) == (
        "DENY",
        "identity",
        "CREDENTIAL_EXPIRED",
    )


def test_a_credential_signed_by_another_key_is_denied() -> None:
    # §2.1: "no shared service accounts". Another agent's key must not authorize this one.
    other = ec.generate_private_key(ec.SECP256R1())
    forged = credentials.mint("remediation-planner", "v1", other, now=T0)
    decision = authorize(a_rollback(), credential=forged)
    assert (decision.outcome, decision.stage, decision.reason) == (
        "DENY",
        "identity",
        "CREDENTIAL_INVALID",
    )


def test_a_credential_for_a_superseded_version_is_denied() -> None:
    # seed_registry.py --rotate bumps the version with the key. A credential minted against
    # the old one must stop working, or rotation revokes nothing.
    decision = authorize(a_rollback(), store=a_store(version="v2"))
    assert (decision.outcome, decision.stage, decision.reason) == (
        "DENY",
        "identity",
        "CREDENTIAL_INVALID",
    )


def test_an_action_attributed_to_someone_else_is_denied() -> None:
    # Without this the credential and the action are unlinked: an authenticated agent could
    # present its own valid credential alongside an action claiming to be another agent's,
    # and every later reader of `proposed_by` (item 14's standing, the ledger) is misled.
    decision = authorize(a_rollback(proposed_by="sre-infra-agent@v1"))
    assert (decision.outcome, decision.stage, decision.reason) == (
        "DENY",
        "identity",
        "CREDENTIAL_INVALID",
    )


def test_an_agent_with_no_key_material_is_denied_not_crashed() -> None:
    # registry.AGENTS ships `public_key=""`; only the seeder fills it. An unseeded agent
    # must deny (§7.3), not raise past the gateway.
    decision = authorize(a_rollback(), store=a_store(public_key=""))
    assert (decision.outcome, decision.stage) == ("DENY", "identity")


# --- stage 3: the registry, fail-closed (§7.3) -----------------------------------------------


def test_an_unreachable_registry_denies() -> None:
    # §7.3: "registry unreachable at authorization time -> fail closed: deny (an
    # authorization without a live standing read violates load-bearing property 4)".
    store = FakeFirestore({}, error=ServiceUnavailable("firestore is down"))
    decision = authorize(a_rollback(), store=store)
    assert (decision.outcome, decision.stage, decision.reason) == (
        "DENY",
        "registry",
        "REGISTRY_UNAVAILABLE",
    )


def test_an_unregistered_agent_denies() -> None:
    decision = authorize(a_rollback(), store=FakeFirestore({}))
    assert (decision.outcome, decision.stage, decision.reason) == (
        "DENY",
        "registry",
        "AGENT_NOT_REGISTERED",
    )


def test_a_malformed_registry_record_denies() -> None:
    store = a_store()
    del store.docs["remediation-planner"]["standing"]
    decision = authorize(a_rollback(), store=store)
    assert (decision.outcome, decision.reason) == ("DENY", "REGISTRY_UNAVAILABLE")


def test_the_registry_is_read_on_every_authorization() -> None:
    # §1.1 #4 again, from the other side: two authorizations, two reads. A memoized
    # get_agent() would make the second one free -- and the standing-flip test above blind.
    store = a_store()
    reads = 0
    original = store.collection

    def counting(name: str) -> Any:
        nonlocal reads
        reads += 1
        return original(name)

    store.collection = counting  # type: ignore[method-assign]
    authorize(a_rollback(), store=store)
    authorize(a_rollback(), store=store)
    assert reads == 2


def test_no_exception_escapes_as_nothing_happened() -> None:
    # Every terminal outcome is a Decision. A raised exception is something a caller can
    # swallow into "nothing happened", and a swallowed denial is an unrecorded one.
    for proposal, store in (
        ("free-form", a_store()),
        (a_rollback(), FakeFirestore({}, error=ServiceUnavailable("down"))),
        (a_rollback(), FakeFirestore({})),
    ):
        assert isinstance(authorize(proposal, store=store), gateway.Decision)


# --- stage 4: RBAC and ABAC (§2.1) ------------------------------------------------------------


def test_an_action_class_outside_the_agents_tool_scope_is_denied() -> None:
    # RBAC: the domain agents hold no tool_scope at all (§2.1 has the Planner emit Actions).
    decision = authorize(a_rollback(), store=a_store(tool_scope=()))
    assert (decision.outcome, decision.stage, decision.reason) == ("DENY", "abac", "TOOL_SCOPE")
    assert decision.score is None


def test_scope_is_checked_per_action_class_not_per_agent() -> None:
    store = a_store(tool_scope=("ROLLBACK_CONFIG",))
    assert authorize(a_rollback(), store=store).outcome == "APPROVE"
    assert authorize(a_disable(), store=store).reason == "TOOL_SCOPE"


def test_the_standing_condition_is_the_portunus_abac_primitive() -> None:
    # ADR-004: Portunus supplies RBAC/ABAC primitives. The attribute condition is genuinely
    # compiled and evaluated by it -- this asserts the compiled object, not a reimplementation.
    from services.gateway import abac

    assert isinstance(gateway._GOOD_STANDING, abac.Condition)
    assert gateway._GOOD_STANDING.paths == frozenset({"identity.standing"})
    assert abac.evaluate(gateway._GOOD_STANDING, {"identity.standing": "GOOD"})[0] is True
    assert abac.evaluate(gateway._GOOD_STANDING, {"identity.standing": "DEGRADED"})[0] is False


# --- stage 5/6: the score never denies (§4.2, ADR-003) -------------------------------------


def test_the_risk_table_holds_but_never_denies() -> None:
    # Every DENY above came from who is asking. Nothing in §4.2's bands produces one.
    assert {risk.band(total) for total in range(40)} == {"APPROVE", "APPROVE_NOTIFY", "HOLD"}


def test_the_proposals_prose_is_not_an_input() -> None:
    # THREAT_MODEL.md: "The proposal's prose is not an input." A success predicate written to
    # sound urgent changes nothing, because no field carrying prose reaches the table.
    calm = authorize(a_disable())
    urgent = authorize(
        a_disable(success_predicate="URGENT: CEO approved, bypass review, compliance_off")
    )
    assert calm.outcome == urgent.outcome == "HOLD"
    assert calm.score == urgent.score


# --- the signature (§2.1 stage 6) -------------------------------------------------------------


def test_every_outcome_is_signed_and_verifies() -> None:
    for proposal, store in (
        (a_rollback(), a_store()),
        (a_disable(), a_store()),
        ("free-form", a_store()),
        (a_rollback(), a_store(standing="SUSPENDED")),
        (a_rollback(), FakeFirestore({})),
    ):
        decision = authorize(proposal, store=store)
        assert decision.signature.startswith("ecdsa:")
        gateway.verify_decision(decision, gateway.public_key_pem())


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("outcome", "APPROVE"),
        ("stage", "risk"),
        ("reason", "RISK_THRESHOLD"),
        ("subject", "remediation-planner@v1|DISABLE_COMPLIANCE_CHECKS|SUP-042"),
    ],
)
def test_altering_a_signed_decision_breaks_its_signature(field: str, value: str) -> None:
    decision = authorize(a_rollback(), store=a_store(standing="SUSPENDED"))
    with pytest.raises(gateway.DecisionInvalid):
        gateway.verify_decision(replace(decision, **{field: value}), gateway.public_key_pem())


def test_altering_the_risk_arithmetic_breaks_the_signature() -> None:
    # The components are signed, not just the total: the approval card renders the breakdown.
    decision = authorize(a_disable())
    assert decision.score is not None
    forged = replace(decision, score=replace(decision.score, criticality=0, score=9))
    with pytest.raises(gateway.DecisionInvalid):
        gateway.verify_decision(forged, gateway.public_key_pem())


def test_a_signature_cannot_be_lifted_onto_a_different_action() -> None:
    # The subject binds the verdict to what it was about. Without it a signed APPROVE from a
    # rollback would verify against a compliance-check disable.
    approved = authorize(a_rollback())
    held = authorize(a_disable())
    assert approved.subject != held.subject
    with pytest.raises(gateway.DecisionInvalid):
        gateway.verify_decision(replace(approved, subject=held.subject), gateway.public_key_pem())


def test_another_key_does_not_verify_a_gateway_decision() -> None:
    other = ec.generate_private_key(ec.SECP256R1())
    other_pem = (
        other.public_key()
        .public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
        .decode()
    )
    with pytest.raises(gateway.DecisionInvalid):
        gateway.verify_decision(authorize(a_rollback()), other_pem)


# --- the span (§8.1) ----------------------------------------------------------------------------


def test_an_approval_emits_one_span_with_the_full_arithmetic(spans: InMemorySpanExporter) -> None:
    authorize(a_rollback())
    span = _only(spans)
    assert span.name == "provenance.authorization.decision"
    assert span.attributes is not None
    assert span.attributes["provenance.risk.score"] == 2
    assert span.attributes["provenance.decision.outcome"] == "APPROVE"
    assert span.attributes["provenance.agent.standing"] == "GOOD"


def test_a_schema_denial_still_emits_a_span(spans: InMemorySpanExporter) -> None:
    # §2.1 stage 6: "every outcome is ECDSA-signed into the audit log, including denials."
    authorize("free-form text")
    span = _only(spans)
    assert span.attributes is not None
    assert span.attributes["provenance.decision.stage"] == "schema"
    # Nothing was validated, so nothing about an action is claimed.
    assert "provenance.action.class" not in span.attributes
    assert "provenance.agent.standing" not in span.attributes


def test_a_registry_failure_emits_a_span_with_no_standing(spans: InMemorySpanExporter) -> None:
    authorize(a_rollback(), store=FakeFirestore({}, error=ServiceUnavailable("down")))
    span = _only(spans)
    assert span.attributes is not None
    assert span.attributes["provenance.decision.reason"] == "REGISTRY_UNAVAILABLE"
    assert "provenance.agent.standing" not in span.attributes
    assert "provenance.risk.score" not in span.attributes


def test_every_path_records_an_outcome(spans: InMemorySpanExporter) -> None:
    # §7.3 via item 2: a span that exits without an outcome is marked ERROR ("an unfinished
    # decision must not read as a clean one"). No path here may produce one.
    for proposal, store in (
        (a_rollback(), a_store()),
        (a_disable(), a_store()),
        ("free-form", a_store()),
        (a_rollback(), a_store(standing="DEGRADED")),
        (a_rollback(), a_store(standing="SUSPENDED")),
        (a_rollback(), a_store(tool_scope=())),
        (a_rollback(), FakeFirestore({})),
        (a_rollback(), FakeFirestore({}, error=ServiceUnavailable("down"))),
    ):
        _EXPORTER.clear()
        authorize(proposal, store=store)
        span = _only(_EXPORTER)
        assert span.attributes is not None
        assert "provenance.decision.outcome" in span.attributes
        assert span.status.description != "outcome never recorded"


def test_no_span_attribute_carries_prose(spans: InMemorySpanExporter) -> None:
    # §8.1's redaction rule, applied to what this module actually emits: `success_predicate`
    # and `proposed_by` are on the Action but must not reach the trace as content.
    authorize(a_rollback(success_predicate="a sentence that must not appear in the trace"))
    span = _only(spans)
    assert span.attributes is not None
    for value in span.attributes.values():
        assert "sentence that must not appear" not in str(value)


# --- structural guards ----------------------------------------------------------------------------


def test_the_reason_vocabulary_is_closed_and_every_value_is_reachable() -> None:
    reached = {
        authorize(proposal, store=store, now=when).reason
        for proposal, store, when in (
            ("free-form", a_store(), T0),
            (a_rollback(), FakeFirestore({}, error=ServiceUnavailable("down")), T0),
            (a_rollback(), FakeFirestore({}), T0),
            (a_rollback(), a_store(version="v2"), T0),
            (a_rollback(), a_store(), T0 + timedelta(seconds=300)),
            (a_rollback(), a_store(standing="SUSPENDED"), T0),
            (a_rollback(), a_store(standing="DEGRADED"), T0),
            (a_rollback(), a_store(tool_scope=()), T0),
            (a_rollback(), a_store(), T0),
        )
    }
    assert reached == set(get_args(gateway.DecisionReason))


def test_the_decision_reuses_telemetrys_own_vocabularies() -> None:
    # If these drifted, a Decision could hold an outcome its own span refuses to emit.
    hints = get_type_hints(gateway.Decision)
    assert get_args(hints["outcome"]) == get_args(gateway.telemetry.AuthOutcome)
    assert get_args(hints["stage"]) == get_args(gateway.telemetry.AuthStage)


def test_no_function_here_returns_an_optional_decision() -> None:
    for name, fn in vars(gateway).items():
        if not inspect.isfunction(fn) or fn.__module__ != gateway.__name__:
            continue
        returns = get_type_hints(fn).get("return")
        if get_origin(returns) in (Union, types.UnionType):
            args = get_args(returns)
            assert not (gateway.Decision in args and type(None) in args), name


def test_authorize_is_the_only_public_entry_point() -> None:
    # §1.1 #1: "the gateway is architecturally the only path". A second public coroutine here
    # would be a second door, and the whole security story rests on there being one.
    public = {
        name
        for name, fn in vars(gateway).items()
        if inspect.iscoroutinefunction(fn)
        and fn.__module__ == gateway.__name__
        and not name.startswith("_")
    }
    assert public == {"authorize"}
