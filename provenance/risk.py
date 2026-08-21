"""The deterministic risk table — §4.2, the determinism boundary's one address (item 7).

`ARCHITECTURE.md` §4.1 states the rule this module exists to satisfy: a deterministic
decision "may not consume a number an LLM produced." §4.2 then makes risk a pure lookup
over the typed Action's declared fields — and `provenance/action.py` has already checked
every one of those fields against an authority that is not the Planner, so the numbers
added up here describe properties the action objectively has.

    risk = base[action_class]
         + criticality_points[target_tier]     # tier1 +2, tier2 +1, tier3 0
         + blast_points[blast_radius]          # org-wide +2, multi-service +1, single +0
         + irreversibility_points[reversible]  # effects-irreversible +3, reversible +0

    0-3  -> auto-approve
    4-6  -> auto-approve with notification
    7+   -> HOLD for human approval

Nothing here is configurable, learnable, or weighted. ADR-003 rejected LLM risk assessment
("persuadable, unexplainable, unauditable"), trained anomaly scorers, and per-action
hardcoded outcomes without arithmetic — the last because the approval card (item 31) is
built from the additive explanation, not from the total.

`base` lives here rather than on `tools.Tool` for the reason ADR-011 gave: every risk
component belongs in one place, so a change to the table is a change to one file.

Pure, synchronous, no I/O, no span. The component that *decides* emits — `gateway.py`.
"""

from __future__ import annotations

from dataclasses import dataclass

from provenance.action import Action
from provenance.telemetry import AuthOutcome, BlastRadius, Tier

# One entry per `tools.TOOLS` entry, and a test asserts the two key sets are equal — a third
# tool cannot ship without a base score, which would otherwise fail at authorization time.
# The two values are not free: §4.2's worked examples fix them by arithmetic (see below).
BASE: dict[str, int] = {
    "ROLLBACK_CONFIG": 1,
    "DISABLE_COMPLIANCE_CHECKS": 4,
}

CRITICALITY: dict[Tier, int] = {"tier1": 2, "tier2": 1, "tier3": 0}

BLAST: dict[BlastRadius, int] = {"org-wide": 2, "multi-service": 1, "single-service": 0}

# Keyed by `Action.reversible`, so the table reads in the same direction the field does.
# §4.2 words it the other way round ("effects-irreversible +3"), which is the same rule.
IRREVERSIBILITY: dict[bool, int] = {False: 3, True: 0}

# §4.2's bands. The upper edge of each, not the lower, so `band()` reads as a ladder.
APPROVE_CEILING = 3
NOTIFY_CEILING = 6


@dataclass(frozen=True)
class RiskScore:
    """§4.2's arithmetic, kept as components rather than a total.

    The gateway ledger and the approval card both render the breakdown component by
    component (§8.1), and `telemetry.set_risk()` refuses to emit a score that does not
    equal its parts — so the components are the object and the total is derived from them.
    """

    base: int
    criticality: int
    blast: int
    irreversibility: int
    score: int


def score(action: Action) -> RiskScore:
    """Look up §4.2's four components for a validated Action and add them.

    Takes an `Action`, not a proposal: every field read here was checked against its
    authority by `action.validate()`, which is what makes the lookup meaningful rather
    than a sum of the Planner's own claims.
    """
    base = BASE[action.action_class]
    criticality = CRITICALITY[action.target_tier]
    blast = BLAST[action.blast_radius]
    irreversibility = IRREVERSIBILITY[action.reversible]
    return RiskScore(
        base=base,
        criticality=criticality,
        blast=blast,
        irreversibility=irreversibility,
        score=base + criticality + blast + irreversibility,
    )


def band(total: int) -> AuthOutcome:
    """§4.2's three bands. Never DENY: the table holds actions, it does not reject them.

    A denial comes from identity, the registry or tool scope — from *who is asking*, never
    from the score. The score's worst answer is "a human decides".
    """
    if total <= APPROVE_CEILING:
        return "APPROVE"
    if total <= NOTIFY_CEILING:
        return "APPROVE_NOTIFY"
    return "HOLD"
