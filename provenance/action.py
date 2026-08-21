"""The typed Action and its mechanical validation — §2.1 stage 1 (item 6).

`ARCHITECTURE.md` §3.1 gives the Remediation Planner exactly one output format, and §2.1 makes
validating it the first stage of the action pipeline: the `action_class` must exist in the tool
registry, the `target` must exist in the entity model, and the declared fields must validate
against the tool schema. §7.1's promise — "a hallucinated action dies at schema validation,
before the gateway ever sees it" — is this module. "Before the gateway" means before identity,
the registry read, ABAC and the risk table: a rejection here reaches none of them.

Nothing in this module reasons, reads a network, or consults a model. Every check is a set
membership or an equality against a value some *other* authority owns:

| Field | Authority it is checked against |
|---|---|
| `action_class` | `provenance/tools.py` |
| `target` | `provenance/synthetic/company.py` (the entity model) |
| `target_tier` | the target entity's own `tier` |
| `reversible`, `blast_radius` | the tool's, never the Planner's |

That last row is the load-bearing one. §3.1: "the tool registry knows that
`DISABLE_COMPLIANCE_CHECKS` is irreversible and org-wide, so a Planner claiming otherwise fails
validation. Not vibes." It is also what makes ADR-003's risk table safe to be a pure lookup —
the numbers it adds up describe properties the action objectively has.

Fail-closed, the same way `registry.py` is: every failure raises, no function returns an
optional Action, and item 7's gateway catches `ActionError` once and maps it to
`DENY(stage="schema")` — the stage `telemetry.AuthStage` already reserves. This module emits no
span itself; validation is a data check, and the component that *decides* is the one that
emits, exactly as item 5 left the `authorization.decision` span to item 7.

`outcome_for()` is §7.1's other half — "returned to the Planner exactly once; a second malformed
emission escalates the incident to a human" — as arithmetic. It holds no state: item 9's control
loop owns the count, because §7.1 is explicit that "no agent owns its own iteration count — the
control loop does, in code." Shipped and tested here so item 9 inherits a checked rule, the way
`registry.degraded_by_window()` shipped ahead of item 14.

Schema reasoning in `docs/adr/ADR-011`.
"""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any, Literal, get_args

from provenance import tools
from provenance.synthetic import company
from provenance.telemetry import BlastRadius, Tier

# §7.1: one rejection, then escalation. The Planner gets `MALFORMED_RETRY_BUDGET` corrections;
# the attempt after that is a human's problem. Named so item 9 points at a number, not a phrase
# -- the same treatment §3.4's rolling window got in item 5.
MALFORMED_RETRY_BUDGET = 1

MalformedOutcome = Literal["REJECT", "ESCALATE"]

# `proposed_by` is §3.1's "agent id + version" as one string, matching how the registry keys an
# agent (`agents/{id}`) and versions it (`v1`, `v42`). Item 7 splits it to look the agent up.
_PROPOSED_BY = re.compile(r"^[a-z0-9-]+@v[0-9]+$")


@dataclass(frozen=True)
class Action:
    """§3.1's typed Action, verbatim: eight fields, no more.

    There is deliberately no `params` field. §4.2 writes the worked example as
    `ROLLBACK_CONFIG(inventory-api, v42->v41)`, but the versions are not the Planner's to
    choose: item 10's executor reads `known_good_version` off the service in the entity model.
    An open parameters field would be a typed channel an LLM could put anything through, on the
    one object the whole determinism boundary is a pure function of. See `docs/adr/ADR-011`.
    """

    action_class: str
    target: str
    target_tier: Tier
    blast_radius: BlastRadius
    reversible: bool
    evidence_refs: tuple[str, ...]
    success_predicate: str
    proposed_by: str


class ActionError(Exception):
    """Base for every validation failure. Item 7 catches this and denies at stage `schema`."""


class NotATypedAction(ActionError):
    """The proposal is not §3.1's shape at all -- free-form text, a wrong field, a bad type."""


class UnknownTool(ActionError):
    """`action_class` names no tool in the registry. The fabricated-tool case."""


class UnknownTarget(ActionError):
    """`target` is absent from the entity model, or is not the kind this tool acts on."""


class FieldMismatch(ActionError):
    """A declared field contradicts the authority that owns it (§3.1's "not vibes")."""


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise NotATypedAction(message)


def _string(data: Mapping[str, Any], key: str) -> str:
    value = data[key]
    _require(isinstance(value, str) and value != "", f"{key}: expected a non-empty string")
    assert isinstance(value, str)
    return value


# Two monomorphic checkers rather than one generic helper, mirroring `registry._check_standing`:
# the Literal has to be named at the call site for mypy to narrow to it.


def _check_tier(value: object) -> Tier:
    _require(value in get_args(Tier), f"target_tier: {value!r} is not one of {get_args(Tier)}")
    return value  # type: ignore[return-value]


def _check_blast_radius(value: object) -> BlastRadius:
    _require(
        value in get_args(BlastRadius),
        f"blast_radius: {value!r} is not one of {get_args(BlastRadius)}",
    )
    return value  # type: ignore[return-value]


def validate(proposal: object) -> Action:
    """Turn an untrusted proposal into a typed Action, or raise `ActionError` (§2.1 stage 1).

    Accepts `object` on purpose: §10's three cases are a fabricated `action_class`, a
    nonexistent target, and *free-form text*, and the third only dies here if a bare string can
    be handed in. A `str`, `None`, a list and a dict with the wrong keys all enter the same
    door and leave through the same exception hierarchy.
    """
    # 1. Shape. Everything that is not §3.1's object dies before any authority is consulted.
    if not isinstance(proposal, Mapping):
        raise NotATypedAction(f"expected a typed action, got {type(proposal).__name__}")
    expected = {field for field in Action.__dataclass_fields__}
    present = set(proposal)
    _require(
        present == expected,
        f"fields {sorted(present)} are not §3.1's {sorted(expected)}",
    )

    action_class = _string(proposal, "action_class")
    target = _string(proposal, "target")
    target_tier = _check_tier(proposal["target_tier"])
    blast_radius = _check_blast_radius(proposal["blast_radius"])
    success_predicate = _string(proposal, "success_predicate")

    reversible = proposal["reversible"]
    # bool before int: `isinstance(True, int)` is True, so an int would slip through the other way.
    _require(isinstance(reversible, bool), "reversible: expected a boolean")

    evidence_refs = proposal["evidence_refs"]
    _require(
        isinstance(evidence_refs, Sequence) and not isinstance(evidence_refs, str),
        "evidence_refs: expected a sequence of evidence ids",
    )
    _require(len(evidence_refs) > 0, "evidence_refs: an action must cite the evidence grounding it")
    _require(
        all(isinstance(ref, str) and ref != "" for ref in evidence_refs),
        "evidence_refs: every entry must be a non-empty evidence id",
    )

    proposed_by = _string(proposal, "proposed_by")
    _require(
        _PROPOSED_BY.match(proposed_by) is not None,
        f"proposed_by: {proposed_by!r} is not `agent-id@version`",
    )

    # 2. The tool exists. §3.1: "must exist in the tool registry".
    try:
        tool = tools.tool_for(action_class)
    except KeyError:
        raise UnknownTool(f"action_class: {action_class!r} names no tool") from None

    # 3. The target exists, and is the kind this tool acts on. §3.1: "must exist in the entity
    #    model"; ADR-009: "a tool schema that names which it expects".
    look_up = company.service if tool.target_kind == "service" else company.supplier
    try:
        entity = look_up(target)
    except KeyError:
        raise UnknownTarget(
            f"target: no {tool.target_kind} {target!r} in the entity model"
        ) from None

    # 4. The declared fields agree with the authorities that own them. A Planner that misstates
    #    reversibility or blast radius is misstating the risk table's inputs (§4.2, ADR-003).
    if target_tier != entity.tier:
        raise FieldMismatch(
            f"target_tier: declared {target_tier!r}, but {target} is {entity.tier!r}"
        )
    if reversible != tool.reversible:
        raise FieldMismatch(
            f"reversible: declared {reversible!r}, but {action_class} is {tool.reversible!r}"
        )
    if blast_radius != tool.blast_radius:
        raise FieldMismatch(
            f"blast_radius: declared {blast_radius!r}, but {action_class} is {tool.blast_radius!r}"
        )

    return Action(
        action_class=action_class,
        target=target,
        target_tier=target_tier,
        blast_radius=blast_radius,
        reversible=reversible,
        evidence_refs=tuple(evidence_refs),
        success_predicate=success_predicate,
        proposed_by=proposed_by,
    )


def outcome_for(attempts: int) -> MalformedOutcome:
    """§7.1's rule: rejected once, escalated on the second. `attempts` counts this one.

    Stateless on purpose -- item 9's control loop keeps the count alongside its §7.1 retry
    budget, because "no agent owns its own iteration count". This is only the arithmetic.
    """
    if attempts < 1:
        raise ValueError(f"attempts: {attempts} is not a malformed emission")
    return "REJECT" if attempts <= MALFORMED_RETRY_BUDGET else "ESCALATE"
