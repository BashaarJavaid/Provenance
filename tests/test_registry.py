"""The offline half of ROADMAP item 5: the registry's invariants, no credentials.

The live half is `scripts/verify_registry.py`, which flips standing against real Firestore
and re-reads it in the same process. These tests guard the properties later items depend
on -- item 7 reads standing on every authorization, item 14 applies the window arithmetic,
item 28's demo beat is a DEGRADED transition -- so breaking one fails the build here.

The fake store is thirty lines of dict, not a mock framework: the point of the first test
is that a value changing *between two reads* is visible, which needs a store the test can
mutate, not a call recorder.
"""

from __future__ import annotations

import asyncio
import importlib.util
import inspect
import types
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Union, get_args, get_origin, get_type_hints

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from google.api_core.exceptions import NotFound, ServiceUnavailable

from provenance import registry

AGENTS_BY_ID = {agent.id: agent for agent in registry.AGENTS}

# scripts/ is not a package (it is in .gcloudignore and never ships), so the seed script is
# loaded by path. Its keypair generation and version bump are real logic and get checked.
_SEED_PATH = Path(__file__).parent.parent / "scripts" / "seed_registry.py"
_spec = importlib.util.spec_from_file_location("seed_registry", _SEED_PATH)
assert _spec is not None and _spec.loader is not None
seed_registry = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(seed_registry)


# --- the fake store ---------------------------------------------------------------------


class FakeSnapshot:
    def __init__(self, data: dict[str, Any] | None) -> None:
        self._data = data

    @property
    def exists(self) -> bool:
        return self._data is not None

    def to_dict(self) -> dict[str, Any] | None:
        return None if self._data is None else dict(self._data)


class FakeDocument:
    def __init__(self, store: FakeFirestore, doc_id: str) -> None:
        self._store = store
        self._id = doc_id

    async def get(self) -> FakeSnapshot:
        if self._store.error is not None:
            raise self._store.error
        return FakeSnapshot(self._store.docs.get(self._id))

    async def update(self, fields: dict[str, Any]) -> None:
        if self._store.error is not None:
            raise self._store.error
        if self._id not in self._store.docs:
            raise NotFound(self._id)
        self._store.docs[self._id].update(fields)


class FakeFirestore:
    """A dict the test can mutate between reads. `docs` is keyed by document id."""

    def __init__(self, docs: dict[str, dict[str, Any]], error: Exception | None = None) -> None:
        self.docs = docs
        self.error = error

    def collection(self, name: str) -> FakeFirestore:
        assert name == registry.COLLECTION
        return self

    def document(self, doc_id: str) -> FakeDocument:
        return FakeDocument(self, doc_id)


def a_stored_agent(**overrides: Any) -> dict[str, Any]:
    return (
        registry.to_document(
            registry.Agent(
                id="sre-infra-agent",
                version="v1",
                public_key="-----BEGIN PUBLIC KEY-----\nstub\n-----END PUBLIC KEY-----\n",
                tool_scope=(),
                memory_domains=("infrastructure",),
                standing="GOOD",
                rejection_window=(),
            )
        )
        | overrides
    )


# --- the load-bearing property ----------------------------------------------------------


def test_a_standing_flip_between_two_reads_is_visible() -> None:
    # §1.1 property 4 and ARCHITECTURE §10's Gateway row: the registry is read at request
    # time, not at boot. Any memoization -- a dict, an lru_cache, a value captured at
    # import -- makes the second read return GOOD and fails here. This is the offline
    # twin of scripts/verify_registry.py.
    store = FakeFirestore({"sre-infra-agent": a_stored_agent()})

    first = asyncio.run(registry.get_agent("sre-infra-agent", client=store))
    store.docs["sre-infra-agent"]["standing"] = "DEGRADED"
    second = asyncio.run(registry.get_agent("sre-infra-agent", client=store))

    assert [first.standing, second.standing] == ["GOOD", "DEGRADED"]


def test_set_standing_is_visible_to_the_next_read() -> None:
    # The writer and the reader agree, which is what verify_registry.py exercises live.
    store = FakeFirestore({"sre-infra-agent": a_stored_agent()})

    asyncio.run(registry.set_standing("sre-infra-agent", "SUSPENDED", client=store))

    assert asyncio.run(registry.get_agent("sre-infra-agent", client=store)).standing == "SUSPENDED"


# --- fail-closed (§7.3) -----------------------------------------------------------------


def test_an_unreachable_registry_raises_rather_than_answering() -> None:
    # §7.3: "registry unreachable at authorization time -> fail closed: deny". Item 7 can
    # only deny if this raises; a permissive default here would be an authorization
    # granted without a live standing read.
    store = FakeFirestore({}, error=ServiceUnavailable("firestore is down"))

    with pytest.raises(registry.RegistryUnavailable):
        asyncio.run(registry.get_agent("sre-infra-agent", client=store))
    with pytest.raises(registry.RegistryUnavailable):
        asyncio.run(registry.set_standing("sre-infra-agent", "GOOD", client=store))


def test_an_unregistered_agent_raises() -> None:
    # An identity with no registry record is not an anonymous one (§2.1 stage 3).
    store = FakeFirestore({})

    with pytest.raises(registry.AgentNotRegistered):
        asyncio.run(registry.get_agent("ghost-agent", client=store))
    with pytest.raises(registry.AgentNotRegistered):
        asyncio.run(registry.set_standing("ghost-agent", "GOOD", client=store))


def test_both_failures_are_catchable_as_one_registry_error() -> None:
    # Item 7's gateway catches RegistryError once and denies at stage "registry".
    assert issubclass(registry.RegistryUnavailable, registry.RegistryError)
    assert issubclass(registry.AgentNotRegistered, registry.RegistryError)


def test_a_malformed_record_raises_rather_than_defaulting() -> None:
    # A stored standing outside the vocabulary must not quietly read as GOOD, and a record
    # missing a field must not read as a partially-authorized agent.
    with pytest.raises(registry.RegistryError):
        registry.from_document("sre-infra-agent", a_stored_agent(standing="FINE"))
    with pytest.raises(registry.RegistryError):
        registry.from_document("sre-infra-agent", {"id": "sre-infra-agent"})
    with pytest.raises(registry.RegistryError):
        registry.from_document("sre-infra-agent", None)
    with pytest.raises(registry.RegistryError):
        asyncio.run(registry.set_standing("sre-infra-agent", "FINE", client=FakeFirestore({})))  # type: ignore[arg-type]


def test_no_registry_function_returns_an_optional_agent() -> None:
    # The fail-closed posture is structural: `Agent | None` is one forgotten `if agent:`
    # away from failing open, so no function is allowed to return it.
    for name, fn in vars(registry).items():
        if not inspect.isfunction(fn) or fn.__module__ != registry.__name__:
            continue
        returns = get_type_hints(fn).get("return")
        if get_origin(returns) in (Union, types.UnionType):
            args = get_args(returns)
            assert not (registry.Agent in args and type(None) in args), name


# --- the standing rule (§3.4) -----------------------------------------------------------


def test_three_rejections_inside_the_window_degrade_and_two_do_not() -> None:
    # §3.4 / §10's Standing row: "three rejected memory writes lacking verifiable evidence
    # inside the rolling window -> DEGRADED". Item 14 applies this before it writes.
    now = datetime(2026, 8, 21, 12, 0, tzinfo=UTC)

    def entries(*ages_in_hours: float) -> list[registry.RejectionEntry]:
        return [
            registry.RejectionEntry(
                rejected_at=(now - timedelta(hours=age)).isoformat(),
                reason="unverifiable_claim",
            )
            for age in ages_in_hours
        ]

    assert not registry.degraded_by_window(entries(1, 2), now=now)
    assert registry.degraded_by_window(entries(1, 2, 3), now=now)
    # The window rolls: an old rejection stops counting rather than accumulating forever.
    assert not registry.degraded_by_window(entries(1, 2, 25), now=now)
    assert registry.REJECTION_THRESHOLD == 3
    assert registry.REJECTION_WINDOW_HOURS == 24


def test_the_stored_standing_is_authoritative_over_the_window() -> None:
    # §3.4 stores `standing` as a field so a human can reinstate it. A read that recomputed
    # standing from the window would overwrite that decision and could never express
    # SUSPENDED, which no number of rejections produces.
    window = [{"rejected_at": "2026-08-21T11:00:00+00:00", "reason": "unverifiable_claim"}] * 5
    stored = a_stored_agent(standing="GOOD", rejection_window=window)

    assert registry.from_document("sre-infra-agent", stored).standing == "GOOD"


# --- the fixture ------------------------------------------------------------------------


def test_the_fleet_is_the_three_phase_2_identities() -> None:
    assert set(AGENTS_BY_ID) == {"sre-infra-agent", "supply-chain-agent", "remediation-planner"}
    assert len(AGENTS_BY_ID) == len(registry.AGENTS), "agent ids are unique"
    for agent in registry.AGENTS:
        assert agent.version == "v1"
        assert agent.standing == "GOOD"
        assert agent.rejection_window == ()


def test_no_key_material_lives_in_the_repo() -> None:
    # scripts/seed_registry.py generates the keypair at first seed and prints the private
    # half once. A public key checked in here would be one whose private half is nowhere.
    for agent in registry.AGENTS:
        assert agent.public_key == "", agent.id


def test_tool_scope_holds_only_the_action_classes_the_docs_name() -> None:
    # The tool registry is item 6. §4.2 names exactly two action classes; anything else in
    # this field now would be a string item 6 has to either honour or delete.
    assert AGENTS_BY_ID["remediation-planner"].tool_scope == (
        "ROLLBACK_CONFIG",
        "DISABLE_COMPLIANCE_CHECKS",
    )
    # §2.1: the Planner emits the typed Action. The domain agents diagnose; they do not act.
    assert AGENTS_BY_ID["sre-infra-agent"].tool_scope == ()
    assert AGENTS_BY_ID["supply-chain-agent"].tool_scope == ()


def test_each_domain_agent_owns_exactly_one_memory_domain() -> None:
    # §2.2: "the proposing agent must hold registry authority for that memory domain".
    # Item 22's generality number is "one agent file and one registry entry" -- the second
    # domain is already shaped like the first.
    assert AGENTS_BY_ID["sre-infra-agent"].memory_domains == ("infrastructure",)
    assert AGENTS_BY_ID["supply-chain-agent"].memory_domains == ("supply-chain",)
    # The Planner proposes actions, never beliefs. Unused authority is authority to misuse.
    assert AGENTS_BY_ID["remediation-planner"].memory_domains == ()


# --- storage round-trip -----------------------------------------------------------------


def test_a_record_survives_the_round_trip_to_firestore_and_back() -> None:
    # The seeder writes to_document() and the gateway reads from_document(); if the two
    # ever disagree the registry reads as malformed in production and nowhere else.
    original = registry.Agent(
        id="supply-chain-agent",
        version="v3",
        public_key="-----BEGIN PUBLIC KEY-----\nstub\n-----END PUBLIC KEY-----\n",
        tool_scope=("ROLLBACK_CONFIG",),
        memory_domains=("supply-chain",),
        standing="DEGRADED",
        rejection_window=(
            registry.RejectionEntry(rejected_at="2026-08-21T11:00:00Z", reason="unverifiable"),
        ),
    )

    assert registry.from_document(original.id, registry.to_document(original)) == original


# --- the seed script's own logic --------------------------------------------------------


def test_a_generated_public_key_verifies_a_signature_from_its_private_half() -> None:
    # Item 7 verifies a signed assertion against the stored public_key, so what the seeder
    # writes has to be a usable SubjectPublicKeyInfo PEM, not just a plausible string.
    public_pem, private_pem = seed_registry.generate_keypair()
    private = serialization.load_pem_private_key(private_pem.encode(), password=None)
    public = serialization.load_pem_public_key(public_pem.encode())

    signature = private.sign(b"agent-assertion", ec.ECDSA(hashes.SHA256()))

    public.verify(signature, b"agent-assertion", ec.ECDSA(hashes.SHA256()))  # raises if bad
    assert isinstance(public, ec.EllipticCurvePublicKey)
    assert public.curve.name == "secp256r1"


def test_rotating_a_key_bumps_the_version() -> None:
    # A rotated key is a different identity; item 7's assertion carries (agent_id, version).
    assert seed_registry.next_version("v1") == "v2"
    assert seed_registry.next_version("v41") == "v42"
    with pytest.raises(ValueError):
        seed_registry.next_version("latest")
