"""The Agent Registry — identity, scope, and standing, read fresh on every call (item 5).

`ARCHITECTURE.md` §1.1's fourth load-bearing property: **the registry is read at request
time, not at boot.** An agent's standing can change mid-run and the next authorization
must reflect it. That is the whole point of this module, and it is why nothing here
memoizes: `get_agent()` performs one Firestore read per call, every call. The module-level
client is a connection, not a cache. `tests/test_registry.py` mutates a fake store between
two reads and asserts the second one moved; `scripts/verify_registry.py` does the same
against real Firestore.

Fail-closed (§7.3: "registry unreachable at authorization time → deny"): no function here
returns `Agent | None`. A missing record, an unreachable database and a malformed document
all raise. An unhandled exception cannot be mistaken for "allowed", whereas a `None` that
someone forgets to branch on can. Item 7's gateway catches `RegistryError` and maps it to
DENY at stage `"registry"`.

What this module deliberately does not do: mint or verify credentials (item 7 — this only
*stores* `public_key`), append to `rejection_window` (item 14's Memory Policy Engine owns
the memory write path), or emit spans (a registry read is a data access, not a decision;
item 7 emits `authorization.decision` carrying the standing it read here).

Schema reasoning in `docs/adr/ADR-010`. `scripts/seed_registry.py` writes the fixture.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any, get_args

from google.api_core.exceptions import GoogleAPIError, NotFound
from google.cloud import firestore

from provenance.telemetry import Standing

COLLECTION = "agents"

# §3.4 says "three rejected memory writes lacking verifiable evidence inside the rolling
# window", and no document anywhere attaches a size to that window. These two constants
# are where it gets one; ARCHITECTURE.md §3.4 now names them, so item 14 and item 28 have
# a number to point at rather than a phrase. See docs/adr/ADR-010.
REJECTION_THRESHOLD = 3
REJECTION_WINDOW_HOURS = 24


@dataclass(frozen=True)
class RejectionEntry:
    """One rejected memory write. §3.4's `rejection_window` is a list of these.

    §2.2 describes the same thing as a "standing counter incremented"; the counter is the
    length of this list. Item 14 appends an entry on every REJECT; item 5 only reads them.
    """

    rejected_at: str  # ISO-8601 with a Z suffix, matching synthetic/company.py
    reason: str


@dataclass(frozen=True)
class Agent:
    """§3.4's registry record, verbatim. The gateway and the Policy Engine both read this.

    `standing` is the authoritative field: item 14 writes DEGRADED after the third
    rejection and a human writes SUSPENDED. It is deliberately not derived from
    `rejection_window` on read — SUSPENDED is not derivable from rejections at all, and
    §3.4 stores the field precisely so human reinstatement has something to set.
    """

    id: str
    version: str
    public_key: str  # PEM, SubjectPublicKeyInfo. Item 7 verifies signed assertions against it.
    tool_scope: tuple[str, ...]
    memory_domains: tuple[str, ...]
    standing: Standing
    rejection_window: tuple[RejectionEntry, ...]


class RegistryError(Exception):
    """Base for every registry failure. Item 7 catches this and denies (§7.3)."""


class RegistryUnavailable(RegistryError):
    """Firestore could not be reached or answered with an error."""


class AgentNotRegistered(RegistryError):
    """No `agents/{id}` document. An unregistered identity is not an anonymous one."""


# The fleet as of Phase 2. `public_key` is empty here on purpose: key material is generated
# by scripts/seed_registry.py at first seed and never lives in the repo. tool_scope holds
# only the two action classes §4.2 actually names — the tool registry is item 6, and
# inventing more strings now would be guessing at a schema whose owner does not exist yet.
# The domain agents diagnose and propose beliefs; §2.1 has the Planner emit the Action, so
# they hold no tool scope and it holds no memory domain.
AGENTS: tuple[Agent, ...] = (
    Agent(
        id="sre-infra-agent",
        version="v1",
        public_key="",
        tool_scope=(),
        memory_domains=("infrastructure",),
        standing="GOOD",
        rejection_window=(),
    ),
    Agent(
        id="supply-chain-agent",
        version="v1",
        public_key="",
        tool_scope=(),
        memory_domains=("supply-chain",),
        standing="GOOD",
        rejection_window=(),
    ),
    Agent(
        id="remediation-planner",
        version="v1",
        public_key="",
        tool_scope=("ROLLBACK_CONFIG", "DISABLE_COMPLIANCE_CHECKS"),
        memory_domains=(),
        standing="GOOD",
        rejection_window=(),
    ),
)

_client: firestore.AsyncClient | None = None


def _default_client() -> firestore.AsyncClient:
    """The shared connection. Built lazily so importing this module needs no credentials.

    Reusing one client is not caching: it holds a gRPC channel, never a document. Every
    `get_agent()` still round-trips to Firestore.
    """
    global _client
    if _client is None:
        _client = firestore.AsyncClient()
    return _client


def _document(agent_id: str, client: Any | None) -> Any:
    return (
        (client if client is not None else _default_client())
        .collection(COLLECTION)
        .document(agent_id)
    )


def _check_standing(value: object) -> Standing:
    if value not in get_args(Standing):
        raise RegistryError(f"standing: {value!r} is not one of {get_args(Standing)}")
    return value  # type: ignore[return-value]


def to_document(agent: Agent) -> dict[str, Any]:
    """The Firestore payload for one agent. `from_document` is its inverse."""
    return {
        "id": agent.id,
        "version": agent.version,
        "public_key": agent.public_key,
        "tool_scope": list(agent.tool_scope),
        "memory_domains": list(agent.memory_domains),
        "standing": agent.standing,
        "rejection_window": [
            {"rejected_at": entry.rejected_at, "reason": entry.reason}
            for entry in agent.rejection_window
        ],
    }


def from_document(agent_id: str, data: dict[str, Any] | None) -> Agent:
    """Parse a stored record. Raises rather than defaulting on anything malformed."""
    if data is None:
        raise RegistryError(f"{COLLECTION}/{agent_id}: document is empty")
    try:
        return Agent(
            id=data["id"],
            version=data["version"],
            public_key=data["public_key"],
            tool_scope=tuple(data["tool_scope"]),
            memory_domains=tuple(data["memory_domains"]),
            standing=_check_standing(data["standing"]),
            rejection_window=tuple(
                RejectionEntry(rejected_at=e["rejected_at"], reason=e["reason"])
                for e in data["rejection_window"]
            ),
        )
    except (KeyError, TypeError) as exc:
        raise RegistryError(f"{COLLECTION}/{agent_id}: malformed record ({exc})") from exc


async def get_agent(agent_id: str, *, client: Any | None = None) -> Agent:
    """Read one registry record. One Firestore read per call — never cached (§1.1 #4)."""
    try:
        snapshot = await _document(agent_id, client).get()
    except GoogleAPIError as exc:
        raise RegistryUnavailable(f"{COLLECTION}/{agent_id}: {exc}") from exc
    if not snapshot.exists:
        raise AgentNotRegistered(f"{COLLECTION}/{agent_id} is not registered")
    return from_document(agent_id, snapshot.to_dict())


async def set_standing(agent_id: str, standing: Standing, *, client: Any | None = None) -> None:
    """The only writer of standing.

    §3.4: restoration "requires explicit human reinstatement; the system never quietly
    forgives" — so this is a deliberate call, never a side effect of re-seeding.
    scripts/seed_registry.py skips records that already exist precisely so it can never
    reach this state. Item 14 will call this to degrade; a human calls it to reinstate.
    """
    _check_standing(standing)
    try:
        await _document(agent_id, client).update({"standing": standing})
    except NotFound as exc:
        raise AgentNotRegistered(f"{COLLECTION}/{agent_id} is not registered") from exc
    except GoogleAPIError as exc:
        raise RegistryUnavailable(f"{COLLECTION}/{agent_id}: {exc}") from exc


def degraded_by_window(entries: Sequence[RejectionEntry], *, now: datetime) -> bool:
    """§3.4's rule: `REJECTION_THRESHOLD` rejections inside `REJECTION_WINDOW_HOURS`.

    Deliberately not called by `get_agent()` — the stored standing is authoritative. This
    is the arithmetic item 14 applies before it writes DEGRADED, kept here with the two
    constants it depends on and tested now so item 14 inherits a checked rule. `now` is a
    parameter so the test needs no clock mocking.
    """
    cutoff = now - timedelta(hours=REJECTION_WINDOW_HOURS)
    recent = [e for e in entries if datetime.fromisoformat(e.rejected_at) > cutoff]
    return len(recent) >= REJECTION_THRESHOLD
