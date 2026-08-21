"""§2.1 stage 2: a short-lived credential the gateway can check without trusting the agent.

`ARCHITECTURE.md` §2.1 -- "Signature or expiry failure is a terminal denial. No shared
service accounts." -- is `test_a_credential_from_the_wrong_key_is_invalid` and the two
expiry tests. `THREAT_MODEL.md`'s "no shared service accounts" claim is only true if agent
A's credential genuinely fails against agent B's registered key, so that case is asserted
directly rather than assumed from the maths.

No clock is mocked anywhere: `mint()` and `verify()` both take a required `now`, following
`registry.degraded_by_window()`. The expiry-boundary tests sit exactly on `expires_at`.
"""

from __future__ import annotations

import inspect
import types
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from typing import Union, get_args, get_origin, get_type_hints

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from provenance import credentials

T0 = datetime(2026, 8, 21, 12, 0, 0, tzinfo=UTC)


def a_keypair() -> tuple[ec.EllipticCurvePrivateKey, str]:
    """A P-256 pair as (private key, public PEM) -- the shapes seed_registry.py stores."""
    private = ec.generate_private_key(ec.SECP256R1())
    public_pem = (
        private.public_key()
        .public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        .decode()
    )
    return private, public_pem


# --- the round trip -----------------------------------------------------------------------


def test_a_freshly_minted_credential_verifies() -> None:
    private, public_pem = a_keypair()
    cred = credentials.mint("remediation-planner", "v1", private, now=T0)
    credentials.verify(cred, public_pem, now=T0)  # raises on failure; returning is the pass


def test_the_credential_carries_exactly_section_2_1s_four_claims() -> None:
    # §2.1: "an ECDSA-signed assertion (agent_id, agent_version, issued_at, expires_at)".
    # A fifth claim would be something the gateway trusts without an authority behind it.
    assert set(credentials.Credential.__dataclass_fields__) == {
        "agent_id",
        "agent_version",
        "issued_at",
        "expires_at",
        "signature",
    }


def test_the_ttl_is_five_minutes_and_lands_on_expires_at() -> None:
    private, _ = a_keypair()
    cred = credentials.mint("remediation-planner", "v1", private, now=T0)
    assert credentials.CREDENTIAL_TTL_SECONDS == 300
    assert cred.issued_at == "2026-08-21T12:00:00Z"
    assert cred.expires_at == "2026-08-21T12:05:00Z"


# --- expiry (§2.1: "signature or expiry failure is a terminal denial") ----------------------


def test_a_credential_is_valid_one_second_before_it_expires() -> None:
    private, public_pem = a_keypair()
    cred = credentials.mint("remediation-planner", "v1", private, now=T0)
    credentials.verify(cred, public_pem, now=T0 + timedelta(seconds=299))


def test_a_credential_is_expired_at_its_own_expires_at() -> None:
    # The boundary is closed at the top: `expires_at` is the first instant it is not valid.
    private, public_pem = a_keypair()
    cred = credentials.mint("remediation-planner", "v1", private, now=T0)
    with pytest.raises(credentials.CredentialExpired):
        credentials.verify(cred, public_pem, now=T0 + timedelta(seconds=300))


def test_a_credential_from_the_future_is_rejected() -> None:
    # A back-dated clock must not become a way to pre-mint credentials for later use.
    private, public_pem = a_keypair()
    cred = credentials.mint("remediation-planner", "v1", private, now=T0)
    with pytest.raises(credentials.CredentialExpired):
        credentials.verify(cred, public_pem, now=T0 - timedelta(seconds=1))


def test_a_naive_now_is_read_as_utc() -> None:
    # The stored format is `Z`, so a caller passing a naive datetime must not silently get a
    # different verdict from one passing an aware one.
    private, public_pem = a_keypair()
    cred = credentials.mint("remediation-planner", "v1", private, now=T0)
    credentials.verify(cred, public_pem, now=datetime(2026, 8, 21, 12, 1, 0))  # noqa: DTZ001


# --- signature and tampering ---------------------------------------------------------------


def test_a_credential_from_the_wrong_key_is_invalid() -> None:
    # §2.1's "no shared service accounts": agent A's credential must not pass as agent B's.
    private_a, _ = a_keypair()
    _, public_b = a_keypair()
    cred = credentials.mint("remediation-planner", "v1", private_a, now=T0)
    with pytest.raises(credentials.CredentialInvalid):
        credentials.verify(cred, public_b, now=T0)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("agent_id", "sre-infra-agent"),
        ("agent_version", "v2"),
        ("issued_at", "2026-08-21T11:59:00Z"),
        ("expires_at", "2026-08-21T12:59:00Z"),
    ],
)
def test_tampering_with_any_claim_breaks_the_signature(field: str, value: str) -> None:
    # The hash is recomputed from the credential's own claims, so every one of the four is
    # covered by the signature -- including `expires_at`, i.e. expiry cannot be self-extended.
    private, public_pem = a_keypair()
    cred = credentials.mint("remediation-planner", "v1", private, now=T0)
    with pytest.raises(credentials.CredentialInvalid):
        credentials.verify(replace(cred, **{field: value}), public_pem, now=T0)


@pytest.mark.parametrize(
    "signature",
    ["", "deadbeef", "ecdsa:", "ecdsa:nothex", "hmac:deadbeef"],
)
def test_a_malformed_signature_is_invalid_not_a_crash(signature: str) -> None:
    private, public_pem = a_keypair()
    cred = replace(credentials.mint("a", "v1", private, now=T0), signature=signature)
    with pytest.raises(credentials.CredentialInvalid):
        credentials.verify(cred, public_pem, now=T0)


def test_an_unreadable_public_key_is_invalid_not_a_crash() -> None:
    # registry.Agent.public_key is empty in the in-code fixture; only the seeder fills it.
    # An agent seeded without key material must deny, not raise something the gateway misses.
    private, _ = a_keypair()
    cred = credentials.mint("remediation-planner", "v1", private, now=T0)
    with pytest.raises(credentials.CredentialInvalid):
        credentials.verify(cred, "", now=T0)


def test_a_malformed_timestamp_is_invalid_not_a_crash() -> None:
    private, public_pem = a_keypair()
    cred = replace(credentials.mint("a", "v1", private, now=T0), expires_at="whenever")
    with pytest.raises(credentials.CredentialInvalid):
        credentials.verify(cred, public_pem, now=T0)


# --- structural guards ----------------------------------------------------------------------


def test_verify_returns_none_rather_than_a_boolean() -> None:
    # `if verify(...)` and `if not verify(...)` are one typo apart and one of them fails open.
    # registry.get_agent() raises for the same reason (§7.3).
    assert get_type_hints(credentials.verify)["return"] is type(None)


def test_every_failure_shares_one_base_class() -> None:
    # The gateway catches CredentialError once and denies at stage "identity" (§2.1 stage 2).
    assert issubclass(credentials.CredentialInvalid, credentials.CredentialError)
    assert issubclass(credentials.CredentialExpired, credentials.CredentialError)


def test_no_function_here_returns_an_optional_credential() -> None:
    for name, fn in vars(credentials).items():
        if not inspect.isfunction(fn) or fn.__module__ != credentials.__name__:
            continue
        returns = get_type_hints(fn).get("return")
        if get_origin(returns) in (Union, types.UnionType):
            args = get_args(returns)
            assert not (credentials.Credential in args and type(None) in args), name


def test_minting_and_verifying_never_read_the_clock() -> None:
    # `now` is required on both, following registry.degraded_by_window(): item 9's control
    # loop owns the clock. A default would let a call site quietly stop being deterministic.
    for fn in (credentials.mint, credentials.verify):
        assert inspect.signature(fn).parameters["now"].default is inspect.Parameter.empty
