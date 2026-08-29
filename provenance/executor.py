"""Execution — the one component that changes the world, and only on a signed APPROVE (item 10).

`ARCHITECTURE.md`'s §1 diagram calls this box only "ACTUAL ACTION" and §5's component table
has never named it; ADR-012 closed with "item 10 owns the executor". This is that module,
and §5 now carries it as a `[CODE]` component.

**It is not a second path.** §1.1 property 1 says the gateway is architecturally the only
path from reasoning to a state-mutating action, and the way that stays true once something
actually mutates state is that `execute()` refuses to run without a `Decision` it can
*check*: the signature must verify against this process's gateway key, the outcome must be
an approval, and `decision.subject` must name this action's class and target. A signed
APPROVE for a rollback cannot be carried across onto a different target, because the subject
is inside the signature (item 7). Anything short of all three raises.

The rollback itself is three Firestore fields, because the world is synthetic (§9): deploy
the known-good config version, drop the error rate, mark the service healthy. Two things
about how it gets its numbers are load-bearing:

  * **`known_good_version` is read off the entity model, never off the Action.** §3.1 has
    eight fields and no `params` precisely so this is true (ADR-011): a version the Planner
    supplied would be a typed channel from a model onto stored state.
  * **The fault switches are read fresh, at execution time.** ADR-009 put
    `fault_injection/{id}` in Firestore rather than in deploy config so a fault is one write,
    flippable on camera mid-incident. Reading them at boot, or caching them, would make item
    19's `rollback_fails` and `verification_ambiguous` beats un-recordable. Only the first
    changes what this module writes; the second rides out on the result for the control loop.

Fail-closed like `registry.py`: nothing returns an optional, every Google API failure becomes
`ExecutionError`, and item 10's control loop catches it and escalates without verifying and
without writing a belief (§7.3). No span is emitted here — execution is not a decision; the
`verification.outcome` span that follows is where the trace records what came of it.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from google.api_core.exceptions import GoogleAPIError
from google.cloud import firestore

from provenance import action as action_module
from provenance import gateway
from provenance.synthetic import company

SERVICES = "services"
FAULT_INJECTION = "fault_injection"

# §4.2's two approving bands. HOLD is not one of them: a held action waits for a human
# (§2.1 stage 7), and item 30 owns resuming it.
APPROVING = ("APPROVE", "APPROVE_NOTIFY")

# The action classes this module can actually perform. `risk.BASE` scores two, and only one of
# them has an executor: `DISABLE_COMPLIANCE_CHECKS` exists to be scored 11 and stopped, which is
# the design (`ADR-003`), not a gap. Naming that here rather than leaving it implicit in
# `execute()`'s body gives the approval card something to read -- a card offering "Approve" on
# an action nothing can carry out asks a human a question whose answer cannot be honoured.
EXECUTABLE = ("ROLLBACK_CONFIG",)


@dataclass(frozen=True)
class ExecutionResult:
    """What the executor did, and the §9 switches behind it -- reported, never hidden.

    `rollback_failed` changed what this module wrote. `verification_ambiguous` changed
    nothing here and is carried anyway, because it is read off the same document in the same
    request-time read and the control loop is what acts on it (item 19). Fetching it a second
    time in the graph node would be a second read of one document for one boolean.
    """

    target: str
    from_version: str
    to_version: str
    rollback_failed: bool
    verification_ambiguous: bool = False


@dataclass(frozen=True)
class ServiceState:
    """A service as stored, read fresh. What the Verification Agent is asked to judge."""

    error_rate: float
    config_version: str
    healthy: bool


class ExecutionError(Exception):
    """Execution did not happen. Nothing is verified and nothing is learned on this."""


_client: firestore.AsyncClient | None = None


def _default_client() -> firestore.AsyncClient:
    """The shared connection, built lazily so importing this module needs no credentials."""
    global _client
    if _client is None:
        _client = firestore.AsyncClient()
    return _client


def _document(collection: str, doc_id: str, client: Any | None) -> Any:
    return (
        (client if client is not None else _default_client())
        .collection(collection)
        .document(doc_id)
    )


def _check_authorization(action_: action_module.Action, decision: gateway.Decision) -> None:
    """The three questions that stand between a `Decision` object and a stored write."""
    try:
        gateway.verify_decision(decision, gateway.public_key_pem())
    except gateway.DecisionInvalid as exc:
        raise ExecutionError(f"decision does not verify: {exc}") from exc
    if decision.outcome not in APPROVING:
        raise ExecutionError(f"decision is {decision.outcome}, not an approval")
    # `subject` is "agent@version|action_class|target" and is covered by the signature, so
    # this is what stops an APPROVE being lifted from one action onto another.
    if not decision.subject.endswith(f"|{action_.action_class}|{action_.target}"):
        raise ExecutionError(
            f"decision authorizes {decision.subject!r}, "
            f"not {action_.action_class}({action_.target})"
        )


async def _read(collection: str, doc_id: str, client: Any | None) -> dict[str, Any]:
    try:
        snapshot = await _document(collection, doc_id, client).get()
    except GoogleAPIError as exc:
        raise ExecutionError(f"{collection}/{doc_id}: {exc}") from exc
    if not snapshot.exists:
        raise ExecutionError(f"{collection}/{doc_id} does not exist")
    data: dict[str, Any] | None = snapshot.to_dict()
    if data is None:
        raise ExecutionError(f"{collection}/{doc_id}: document is empty")
    return data


async def execute(
    action_: action_module.Action, decision: gateway.Decision, *, client: Any | None = None
) -> ExecutionResult:
    """Perform one authorized `ROLLBACK_CONFIG`. Raises unless the decision authorizes it."""
    _check_authorization(action_, decision)
    # Before the first read, so the failure names itself. Without this an approved
    # `DISABLE_COMPLIANCE_CHECKS` dies on `fault_injection/{supplier}` not existing -- true, but
    # it reports a missing Firestore document for what is actually a class with no executor.
    if action_.action_class not in EXECUTABLE:
        raise ExecutionError(f"no executor for {action_.action_class}")

    fault = await _read(FAULT_INJECTION, action_.target, client)
    rollback_fails = bool(fault.get("rollback_fails"))
    # Read here rather than in the graph node: one request-time read of one document, and the
    # node that acts on it is the same node that already holds the `ExecutionResult`.
    verification_ambiguous = bool(fault.get("verification_ambiguous"))

    service = company.service(action_.target)
    known_good = service.known_good_version
    if known_good is None:
        raise ExecutionError(f"{action_.target} has no known-good version to roll back to")

    # A failed rollback still *deploys*: the version moves and the fault does not clear. That
    # is what makes item 19's REFUTED honest rather than a skipped write.
    fields: dict[str, Any] = {"current_config_version": known_good}
    if not rollback_fails:
        fields["error_rate"] = service.error_rate
        fields["healthy"] = True
    try:
        await _document(SERVICES, action_.target, client).update(fields)
    except GoogleAPIError as exc:
        raise ExecutionError(f"{SERVICES}/{action_.target}: {exc}") from exc

    return ExecutionResult(
        target=action_.target,
        from_version=service.current_config_version or "unknown",
        to_version=known_good,
        rollback_failed=rollback_fails,
        verification_ambiguous=verification_ambiguous,
    )


async def read_state(target: str, *, client: Any | None = None) -> ServiceState:
    """Re-read the service after execution. The measurement, not the intention.

    A separate read rather than an echo of what `execute()` wrote: the Verification Agent is
    asked to judge observed state against a pre-declared predicate, and handing it the write
    payload back would be asking it to check that we meant what we said.
    """
    data = await _read(SERVICES, target, client)
    try:
        return ServiceState(
            error_rate=float(data["error_rate"]),
            config_version=str(data["current_config_version"]),
            healthy=bool(data["healthy"]),
        )
    except (KeyError, TypeError, ValueError) as exc:
        raise ExecutionError(f"{SERVICES}/{target}: malformed service record ({exc})") from exc
