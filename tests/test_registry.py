"""The offline half of ROADMAP item 5: the registry's invariants, no credentials.

The live half is `scripts/verify_registry.py`, which flips standing against real Firestore
and re-reads it in the same process. These tests guard the properties later items depend
on -- item 7 reads standing on every authorization, item 14's `record_rejection()` applies
the window arithmetic and writes DEGRADED, item 28's demo beat is that transition on screen
-- so breaking one fails the build here.

The fake store is thirty lines of dict, not a mock framework: the point of the first test
is that a value changing *between two reads* is visible, which needs a store the test can
mutate, not a call recorder.
"""

from __future__ import annotations

import asyncio
import importlib.util
import inspect
import types
from collections.abc import AsyncIterator
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Union, get_args, get_origin, get_type_hints

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from google.api_core.exceptions import AlreadyExists, NotFound, ServiceUnavailable

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
    def __init__(self, data: dict[str, Any] | None, doc_id: str = "") -> None:
        self._data = data
        self.id = doc_id

    @property
    def exists(self) -> bool:
        return self._data is not None

    def to_dict(self) -> dict[str, Any] | None:
        return None if self._data is None else dict(self._data)


class FakeDocument:
    def __init__(self, store: FakeFirestore, docs: dict[str, dict[str, Any]], doc_id: str) -> None:
        self._store = store
        self._docs = docs
        self._id = doc_id

    async def get(self) -> FakeSnapshot:
        if self._store.error is not None:
            raise self._store.error
        return FakeSnapshot(self._docs.get(self._id), self._id)

    async def update(self, fields: dict[str, Any]) -> None:
        if self._store.error is not None:
            raise self._store.error
        if self._id not in self._docs:
            raise NotFound(self._id)
        self._docs[self._id].update(fields)

    async def create(self, payload: dict[str, Any]) -> None:
        """Firestore's create-if-absent. Item 10's Policy Engine writes beliefs through it."""
        if self._store.error is not None:
            raise self._store.error
        if self._id in self._docs:
            raise AlreadyExists(self._id)
        self._docs[self._id] = dict(payload)


class FakeFirestore:
    """A dict the test can mutate between reads. `docs` is keyed by document id.

    Item 5 needed one collection (`agents`) and `docs` is still it, so every registry test
    reads unchanged. Item 10 added the executor and the Policy Engine, which read `services`
    and `fault_injection` and write `beliefs`, so extra collections are passed by keyword and
    live in `collections` alongside it.
    """

    def __init__(
        self,
        docs: dict[str, dict[str, Any]],
        error: Exception | None = None,
        **collections: dict[str, dict[str, Any]],
    ) -> None:
        self.docs = docs
        self.error = error
        self.collections: dict[str, dict[str, Any]] = {registry.COLLECTION: docs, **collections}

    def collection(self, name: str) -> _FakeCollection:
        return _FakeCollection(self, self.collections.setdefault(name, {}))


class _FakeCollection:
    def __init__(self, store: FakeFirestore, docs: dict[str, dict[str, Any]]) -> None:
        self._store = store
        self._docs = docs

    def document(self, doc_id: str) -> FakeDocument:
        return FakeDocument(self._store, self._docs, doc_id)

    async def stream(self) -> AsyncIterator[FakeSnapshot]:
        """Item 16's `beliefs.class_statements()` enumerates a whole collection, unfiltered."""
        if self._store.error is not None:
            raise self._store.error
        for doc_id, data in list(self._docs.items()):
            yield FakeSnapshot(data, doc_id)

    def where(self, *, filter: Any) -> _FakeQuery:
        """Two callers, two operators: item 15's `audit.flag()` and item 30's `pending()`."""
        field, op, value = filter.field_path, filter.op_string, filter.value
        if op not in ("array_contains", "=="):
            raise NotImplementedError(f"the fake store supports array_contains and ==, not {op!r}")
        return _FakeQuery(self._store, self._docs, field, op, value)


class _FakeQuery:
    def __init__(
        self,
        store: FakeFirestore,
        docs: dict[str, dict[str, Any]],
        field: str,
        op: str,
        value: Any,
    ) -> None:
        self._store = store
        self._docs = docs
        self._field = field
        self._op = op
        self._value = value

    def _matches(self, data: dict[str, Any]) -> bool:
        if self._op == "==":
            return bool(data.get(self._field) == self._value)
        return bool(self._value in data.get(self._field, []))

    async def stream(self) -> AsyncIterator[FakeSnapshot]:
        if self._store.error is not None:
            raise self._store.error
        for doc_id, data in list(self._docs.items()):
            if self._matches(data):
                yield FakeSnapshot(data, doc_id)


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


# --- the standing counter (§2.2 stage 6, item 14) ----------------------------------------

NOW = datetime(2026, 8, 22, 12, 0, tzinfo=UTC)


def a_rejecting_store(**overrides: Any) -> FakeFirestore:
    return FakeFirestore({"sre-infra-agent": a_stored_agent(**overrides)})


def reject(store: FakeFirestore, reason: str = "BELOW_THRESHOLD", *, hours: float = 0.0) -> str:
    agent = asyncio.run(registry.get_agent("sre-infra-agent", client=store))
    return asyncio.run(
        registry.record_rejection(agent, reason, now=NOW - timedelta(hours=hours), client=store)
    )


def stored_window(store: FakeFirestore) -> list[dict[str, Any]]:
    window = store.docs["sre-infra-agent"]["rejection_window"]
    assert isinstance(window, list)
    return window


def test_one_rejection_appends_an_entry_and_leaves_standing_alone() -> None:
    # §2.2 stage 6: "REJECT (logged, standing counter incremented)". The counter is the
    # length of the list (ADR-010), so incrementing it is appending one entry -- and one
    # rejection is not three, so nothing about the agent's authority changes yet.
    store = a_rejecting_store()

    assert reject(store) == "GOOD"

    assert stored_window(store) == [
        {"rejected_at": "2026-08-22T12:00:00Z", "reason": "BELOW_THRESHOLD"}
    ]
    assert store.docs["sre-infra-agent"]["standing"] == "GOOD"


def test_the_third_rejection_inside_the_window_writes_degraded_and_the_second_does_not() -> None:
    # ARCHITECTURE §10's Standing row and §3.4's rule, as the stored document sees it. The
    # arithmetic runs over the *appended* window, so the third call is the one that degrades:
    # applying it to the pre-append list would degrade on the fourth.
    store = a_rejecting_store()

    assert reject(store, hours=2) == "GOOD"
    assert reject(store, hours=1) == "GOOD"
    assert store.docs["sre-infra-agent"]["standing"] == "GOOD"

    assert reject(store) == "DEGRADED"

    assert store.docs["sre-infra-agent"]["standing"] == "DEGRADED"
    assert len(stored_window(store)) == 3
    # The next read sees it -- this is the value item 7 denies on and item 28 renders.
    assert asyncio.run(registry.get_agent("sre-infra-agent", client=store)).standing == "DEGRADED"


def test_a_rejection_that_has_aged_out_stops_counting_but_is_never_pruned() -> None:
    # The window rolls (§3.4), so two recent rejections beside one from last week are not
    # three. The aged entry stays in the document regardless: `degraded_by_window()` filters
    # on read, and the record of why an agent degraded is what item 28's panel shows.
    store = a_rejecting_store()

    assert reject(store, hours=25) == "GOOD"
    assert reject(store, hours=2) == "GOOD"
    assert reject(store) == "GOOD"

    assert store.docs["sre-infra-agent"]["standing"] == "GOOD"
    assert len(stored_window(store)) == 3, "nothing is ever removed from the window"


def test_the_written_timestamp_is_the_one_the_window_arithmetic_can_read() -> None:
    # `record_rejection()` writes the Z form the field's docstring claims; `degraded_by_window()`
    # parses with `fromisoformat`. If those two ever disagree the counter silently stops
    # counting, so the round trip is asserted rather than assumed.
    store = a_rejecting_store()
    reject(store)

    entry = registry.from_document(
        "sre-infra-agent", store.docs["sre-infra-agent"]
    ).rejection_window
    assert entry[0].rejected_at.endswith("Z")
    assert registry.degraded_by_window(entry * 3, now=NOW)


def test_an_unregistered_agent_cannot_have_a_rejection_recorded() -> None:
    # Fail-closed (§7.3), the same mapping `set_standing()` uses: a write to a record that is
    # not there raises rather than creating one. A registry entry is minted by the seeder.
    store = a_rejecting_store()
    agent = asyncio.run(registry.get_agent("sre-infra-agent", client=store))
    store.docs.clear()

    with pytest.raises(registry.AgentNotRegistered):
        asyncio.run(registry.record_rejection(agent, "BELOW_THRESHOLD", now=NOW, client=store))


def test_an_unreachable_registry_raises_rather_than_silently_dropping_the_counter() -> None:
    # The Policy Engine suppresses this deliberately (a refused belief is refused either way),
    # but it has to be raised to be suppressed -- a swallow here would be invisible.
    store = a_rejecting_store()
    agent = asyncio.run(registry.get_agent("sre-infra-agent", client=store))
    store.error = ServiceUnavailable("firestore is down")

    with pytest.raises(registry.RegistryUnavailable):
        asyncio.run(registry.record_rejection(agent, "BELOW_THRESHOLD", now=NOW, client=store))


# --- the fixture ------------------------------------------------------------------------


def test_the_fleet_is_the_identities_that_hold_authority() -> None:
    # The three Phase 2 identities plus item 23's Memory Analyst. The Orchestrator and the
    # Verification Agent are deliberately absent: §3.4 records authority, and neither proposes
    # an action nor writes a belief, so there is nothing about them to record.
    assert set(AGENTS_BY_ID) == {
        "sre-infra-agent",
        "supply-chain-agent",
        "memory-analyst",
        "remediation-planner",
    }
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
