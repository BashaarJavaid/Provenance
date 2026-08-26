#!/usr/bin/env python3
"""ROADMAP item 31's `verify:` line: a non-engineer can read the card and say why it was held.

    .venv/bin/python scripts/verify_approval_card.py
    PROVENANCE_SERVICE_URL=https://provenance-...run.app \
        .venv/bin/python scripts/verify_approval_card.py

Runs against a local `uvicorn provenance.app:app` by default, or the deployed service when
`PROVENANCE_SERVICE_URL` is set — `scripts/verify_belief_inspector.py`'s two-mode shape, and
its posture: **mutates nothing**, needs no token, and can run as many times as you like.

**It deliberately parks nothing.** A stranded `PARKED` record is somebody's unanswered
question, and it blocks `scripts/verify_approval_queue.py`, whose guard refuses a non-empty
queue. So this reads what is already waiting and refuses if nothing is — park one first with
`scripts/verify_supply_chain.py` (the score-11 case) or `scripts/verify_approval_queue.py
--park-only` (the DEGRADED score-2 case).

What it asserts, and why each one is here rather than being obvious:

- **The four components add up to the score beside them.** `telemetry.set_risk()` enforces
  that at emit; this is the same rule on the read side, because a rendered arithmetic that
  does not reproduce its own total is decoration and §4.2's whole defence is that the number
  is a lookup anyone can check.
- **The hold reason agrees with the score.** `RISK_THRESHOLD` over anything below 7 would be
  the card claiming §4.2 held an action §4.2 would have approved. The converse is the
  interesting one and is *not* an error: `STANDING_DEGRADED` over a 2 is the sentence the
  surface exists to print (`ROADMAP.md` item 30's DEGRADED hold at `1 + 1 + 0 + 0 = 2`).
- **Every field the card renders is in the payload.** The card cannot show what the route did
  not serve, and the failure mode of a hand-written renderer is a silent `undefined`.
- **The trigger facts and `entity_ids` are present**, because "why" is generated from them and
  from nothing else — no model is asked what this action is for (item 31's own words).

Then it prints the card as prose, so the half of the `verify:` line that is a human act has
something to hand over. The offline half is the "approval card, item 31" block in
`tests/test_app.py`.
"""

from __future__ import annotations

import os
import sys

import httpx

DEFAULT_URL = "http://127.0.0.1:8000"
COMPONENTS = ("base", "criticality", "blast", "irreversibility")
HOLD_REASONS = ("RISK_THRESHOLD", "STANDING_DEGRADED")
# Everything the browser reads off one queue entry. Kept as a list rather than left implicit
# so adding a line to the card without widening the route fails here instead of on camera.
CARD_FIELDS = (
    "id",
    "parked_at",
    "routed_to",
    "entity_ids",
    "trigger_target",
    "trigger_signal",
    "trigger_observed_value",
    "proposal",
    "risk",
    "hold_reason",
)
PROPOSAL_FIELDS = (
    "action_class",
    "target",
    "target_tier",
    "blast_radius",
    "reversible",
    "success_predicate",
    "proposed_by",
)


class Failed(Exception):
    """A check did not hold."""


def check(condition: bool, message: str) -> None:
    if not condition:
        raise Failed(message)
    print(f"    ok: {message}")


def as_prose(card: dict) -> str:
    """The card in words — what the browser renders, for the human half of the verify line."""
    proposal, risk = card["proposal"], card["risk"]
    rests = (
        "what the organization believes about " + ", ".join(card["entity_ids"])
        if card["entity_ids"]
        else "no stored belief"
    )
    # The *proposing* agent, not `routed_to` -- the domain agent reasons and the Planner
    # proposes, and standing (so the hold reason) is about the proposer. Item 31's live finding.
    proposer = str(proposal["proposed_by"]).split("@")[0]
    lines = [
        (
            f"    {proposer} wants to run {proposal['action_class']}"
            f" on {proposal['target']}, after {card['routed_to']} looked into it."
        ),
        (
            f"    {card['trigger_target']} reported {card['trigger_signal']}"
            f" at {card['trigger_observed_value']}. It rests on {rests}."
        ),
        f"    It would count as having worked when: {proposal['success_predicate']}",
    ]
    if risk is None:
        lines.append("    Not scored — the proposal no longer validates.")
        return "\n".join(lines)
    lines += [
        f"      +{risk['base']:<2} the action itself     {proposal['action_class']}",
        (
            f"      +{risk['criticality']:<2} what it touches       {proposal['target']}"
            f" is {proposal['target_tier']}"
        ),
        f"      +{risk['blast']:<2} how far it reaches    {proposal['blast_radius']}",
        f"      +{risk['irreversibility']:<2} can it be undone      "
        + ("yes" if proposal["reversible"] else "no — this cannot be taken back"),
        f"      ={risk['score']:<2} held because          {card['hold_reason']}",
    ]
    return "\n".join(lines)


def checks(base_url: str) -> None:
    print(f"==> GET {base_url}/approvals  (no token, nothing mutated)")
    response = httpx.get(f"{base_url}/approvals", timeout=30)
    check(
        response.status_code == 200,
        f"the queue answers a cold request with {response.status_code}",
    )
    queue = response.json()
    if not queue:
        raise Failed(
            "the queue is empty, so there is no card to check. Park one first:\n"
            "        scripts/verify_supply_chain.py           (the score-11 hold)\n"
            "        scripts/verify_approval_queue.py --park-only  (the DEGRADED score-2 hold)"
        )
    print(f"    {len(queue)} record(s) waiting for a human")

    for card in queue:
        print(f"==> {card['id']}")
        check(
            all(field in card for field in CARD_FIELDS),
            f"the payload carries every field the card renders: {', '.join(CARD_FIELDS)}",
        )
        check(
            all(field in card["proposal"] for field in PROPOSAL_FIELDS),
            "the proposal carries the four risk-table inputs and the success predicate",
        )
        # "Why" is generated from these and from nothing else. A card with no trigger facts
        # would have to invent the reason, which is exactly what item 31 forbids.
        check(
            bool(card["trigger_target"]) and bool(card["trigger_signal"]),
            f"the trigger facts are stored: {card['trigger_target']}"
            f" / {card['trigger_signal']} at {card['trigger_observed_value']}",
        )
        check(
            isinstance(card["entity_ids"], list),
            f"the beliefs the fleet reasoned from are cited: {card['entity_ids'] or 'none'}",
        )

        risk, reason = card["risk"], card["hold_reason"]
        if risk is None:
            # ADR-032's "the record is an input": a tampered park never reaches §4.2 at all.
            check(reason is None, "an unscored card names no hold reason either")
            print("    (not scored — the proposal no longer validates)")
            continue

        total = sum(risk[component] for component in COMPONENTS)
        check(
            total == risk["score"],
            "the components sum to the score: "
            + " + ".join(str(risk[component]) for component in COMPONENTS)
            + f" = {risk['score']}",
        )
        check(reason in HOLD_REASONS, f"the hold reason is {reason}")
        # §4.2's band, from the other side. A `STANDING_DEGRADED` below 7 is not an error —
        # it is the point — so only the claim that the *table* held it is checked here.
        check(
            reason != "RISK_THRESHOLD" or risk["score"] >= 7,
            f"RISK_THRESHOLD claims §4.2's HOLD band, and {risk['score']} is in it"
            if reason == "RISK_THRESHOLD"
            else f"held on standing, so §4.2's band is not the claim ({risk['score']})",
        )
        if reason == "STANDING_DEGRADED" and risk["score"] < 7:
            print(
                f"    note: this is the sentence the card exists to print — held despite"
                f" scoring only {risk['score']}. §3.4, not §4.2."
            )

    print("\n==> the card, as a non-engineer reads it")
    for card in queue:
        print(as_prose(card))
        print()


def main() -> int:
    base_url = os.environ.get("PROVENANCE_SERVICE_URL", DEFAULT_URL).rstrip("/")
    where = "deployed" if "PROVENANCE_SERVICE_URL" in os.environ else "local"
    print(f"==> approval card, {where}: {base_url}")
    try:
        checks(base_url)
    except Failed as exc:
        print(f"FAIL: {exc}", file=sys.stderr)
        return 1
    except httpx.HTTPError as exc:
        print(f"FAIL: {base_url} is not answering ({exc}).", file=sys.stderr)
        if where == "local":
            print(
                "      Start it with:"
                "  GOOGLE_CLOUD_PROJECT=provenance-hackathon"
                " .venv/bin/python -m uvicorn provenance.app:app",
                file=sys.stderr,
            )
        return 1
    print("==> done. Read the card above and say why it was held. That is the verify line.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
