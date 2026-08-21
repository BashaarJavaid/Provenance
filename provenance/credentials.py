"""Short-lived agent credentials — §2.1 stage 2, minted and verified here (item 7).

`ARCHITECTURE.md` §2.1: "the proposing agent presents a short-lived credential: an
ECDSA-signed assertion `(agent_id, agent_version, issued_at, expires_at)` minted by the
registry and verified here against the agent's registered `public_key`. Signature or expiry
failure is a terminal denial. No shared service accounts."

**Who holds the private half.** Those two clauses only reconcile one way. Verifying against
the *agent's* `public_key` requires signing with the *agent's* private key, and ADR-010
deliberately never stores agent private halves — `scripts/seed_registry.py` prints each one
once and forgets it. So the agent signs its own assertion, and "minted by the registry"
means the registry issued and registered the keypair (and `--rotate` is the only path to a
new one). What the gateway then checks is possession of the private half matching the
public key on the record it just read, which is the property that actually matters: a
compromised or impersonated agent cannot produce it. §2.1 carries a sentence saying so.

**Why this is new code.** ROADMAP item 0.5 confirmed PortunusMCP has no minting layer and no
`expires_at` anywhere — its only TTLs are rate-limit counters, and its identity broker
(`services/gateway/auth.py`) needs Redis, structlog and a YAML policy engine, none of which
belong on Cloud Run for this. So this module is the "thin minting layer" ADR-004 scored on
the track's Agent Identity pillar, built on Portunus's `signing` primitives and nothing else.

Fail-closed like `registry.py` and `action.py`: `verify()` returns `None` or raises. It does
not return a bool, because `if verify(...)` and `if not verify(...)` are one typo apart and
one of them fails open. The gateway catches `CredentialError` once and denies at stage
`"identity"`.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from services.gateway import signing

# §2.1 says only "short-lived" and no document anywhere attaches a number to it — the same
# gap §3.4's rolling window had before item 5 gave it one. Minting and verifying happen in
# the same process microseconds apart, so this is almost entirely slack: five minutes covers
# a paused demo take or a cold Cloud Run start without making an exfiltrated credential
# useful for long.
CREDENTIAL_TTL_SECONDS = 300

# Matches synthetic/company.py and registry.RejectionEntry: ISO-8601, UTC, `Z` suffix.
_TIMESTAMP = "%Y-%m-%dT%H:%M:%SZ"


def _utc(moment: datetime) -> datetime:
    """Normalise to aware UTC. A naive `now` is read as UTC, matching the `Z` in the format.

    Both sides of every comparison below go through this, so a caller passing a naive
    datetime and a caller passing an aware one cannot reach different verdicts.
    """
    return moment.astimezone(UTC) if moment.tzinfo is not None else moment.replace(tzinfo=UTC)


@dataclass(frozen=True)
class Credential:
    """§2.1's signed assertion. Four claims and the signature over them."""

    agent_id: str
    agent_version: str
    issued_at: str
    expires_at: str
    signature: str  # "ecdsa:<hex of the DER signature>"


class CredentialError(Exception):
    """Base for every identity failure. The gateway denies at stage `identity` on this."""


class CredentialInvalid(CredentialError):
    """The signature does not verify against the registered public key, or is malformed."""


class CredentialExpired(CredentialError):
    """`expires_at` has passed, or `issued_at` is in the future."""


def _assertion_hash(credential: Credential) -> str:
    """The hash both sides sign over. One function, so minting and verifying cannot drift.

    Portunus's `signing.sign()` takes a hash *string*, not bytes (ROADMAP item 1 flagged
    this), so this returns a hexdigest. The separator cannot appear in any of the four
    fields — agent ids are `[a-z0-9-]`, versions are `v<n>`, timestamps are ISO-8601 — so
    there is no concatenation ambiguity to exploit.
    """
    joined = (
        f"{credential.agent_id}|{credential.agent_version}"
        f"|{credential.issued_at}|{credential.expires_at}"
    )
    return hashlib.sha256(joined.encode()).hexdigest()


def mint(
    agent_id: str,
    agent_version: str,
    private_key: ec.EllipticCurvePrivateKey,
    *,
    now: datetime,
) -> Credential:
    """Sign an assertion valid for `CREDENTIAL_TTL_SECONDS`.

    `now` is required rather than read from the clock, following
    `registry.degraded_by_window()`: item 9's control loop owns the clock the way it owns
    the malformed-retry count, and a test can sit on an expiry boundary without patching.
    """
    minted_at = _utc(now)
    issued_at = minted_at.strftime(_TIMESTAMP)
    expires_at = (minted_at + timedelta(seconds=CREDENTIAL_TTL_SECONDS)).strftime(_TIMESTAMP)
    unsigned = Credential(
        agent_id=agent_id,
        agent_version=agent_version,
        issued_at=issued_at,
        expires_at=expires_at,
        signature="",
    )
    signature = signing.sign(private_key, _assertion_hash(unsigned))
    return Credential(
        agent_id=agent_id,
        agent_version=agent_version,
        issued_at=issued_at,
        expires_at=expires_at,
        signature=f"ecdsa:{signature.hex()}",
    )


def verify(credential: Credential, public_key_pem: str, *, now: datetime) -> None:
    """Raise unless the credential is well-formed, unexpired, and signed by that key.

    Returns `None` on success. Deliberately not a bool: `registry.get_agent()` raises for
    the same reason — an authorization that fails open because someone wrote `if
    verify(...)` where they meant `if not verify(...)` is exactly the failure §7.3 exists
    to make structurally impossible.
    """
    if not credential.signature.startswith("ecdsa:"):
        raise CredentialInvalid("signature: expected an `ecdsa:<hex>` value")
    try:
        raw = bytes.fromhex(credential.signature.removeprefix("ecdsa:"))
    except ValueError as exc:
        raise CredentialInvalid(f"signature: not hex ({exc})") from exc

    try:
        issued_at = datetime.strptime(credential.issued_at, _TIMESTAMP).replace(tzinfo=UTC)
        expires_at = datetime.strptime(credential.expires_at, _TIMESTAMP).replace(tzinfo=UTC)
    except ValueError as exc:
        raise CredentialInvalid(f"timestamps: {exc}") from exc

    # Expiry is checked before the signature so an expired-but-authentic credential reports
    # the honest reason. Both are terminal denials, so the order costs nothing either way.
    reference = _utc(now)
    if reference >= expires_at:
        raise CredentialExpired(f"expired at {credential.expires_at}")
    if reference < issued_at:
        raise CredentialExpired(f"not valid until {credential.issued_at}")

    try:
        public_key = serialization.load_pem_public_key(public_key_pem.encode())
    except (ValueError, TypeError) as exc:
        raise CredentialInvalid(f"public_key: unreadable PEM ({exc})") from exc
    if not isinstance(public_key, ec.EllipticCurvePublicKey):
        raise CredentialInvalid("public_key: not an EC public key")

    # The hash is recomputed from the credential's own claims, so tampering with any of the
    # four fields changes what is verified and the signature stops matching.
    unsigned = Credential(
        agent_id=credential.agent_id,
        agent_version=credential.agent_version,
        issued_at=credential.issued_at,
        expires_at=credential.expires_at,
        signature="",
    )
    if not signing.verify(public_key, raw, _assertion_hash(unsigned)):
        raise CredentialInvalid(f"signature does not verify for {credential.agent_id}")
