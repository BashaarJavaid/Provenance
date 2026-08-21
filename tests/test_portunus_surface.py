"""Guards the PortunusMCP surface Provenance consumes (ROADMAP item 0.5).

The dependency installs with `--no-deps` outside pyproject.toml, so nothing else
would notice if that step silently stopped working or if the upstream API moved.
These tests fail loudly in that case.
"""

from services.gateway import abac, decision, signing


def test_sign_verify_round_trip() -> None:
    key = signing.generate_private_key()
    # sign() takes a hash *string*, not bytes.
    signature = signing.sign(key, "deadbeef")

    assert signing.verify(key.public_key(), signature, "deadbeef") is True
    assert signing.verify(key.public_key(), signature, "deadbeee") is False


def test_abac_compile_and_evaluate_round_trip() -> None:
    condition = abac.compile_condition("identity.standing == 'GOOD'")

    assert abac.evaluate(condition, {"identity.standing": "GOOD"})[0] is True
    assert abac.evaluate(condition, {"identity.standing": "DEGRADED"})[0] is False


def test_attribute_roots_are_fixed() -> None:
    # Provenance conditions must live under these roots (identity.standing, risk.score).
    # If upstream changes the set, item 7's gateway conditions need revisiting.
    assert abac.ATTRIBUTE_ROOTS == frozenset({"identity", "tool", "context", "risk"})


def test_decision_outcome_vocabulary() -> None:
    # Portunus's vocabulary, not ours: approve/hold/deny maps onto this or we define
    # our own typed decision (item 7 decides which).
    assert {outcome.value for outcome in decision.DecisionOutcome} == {
        "allow",
        "deny",
        "challenge",
        "human_approval_required",
    }
