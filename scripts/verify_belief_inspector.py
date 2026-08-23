#!/usr/bin/env python3
"""ROADMAP item 17's `verify:` line: the inspector shows the computed confidence breakdown.

    .venv/bin/python scripts/verify_belief_inspector.py
    PROVENANCE_SERVICE_URL=https://provenance-...run.app \
        .venv/bin/python scripts/verify_belief_inspector.py

Runs against a local `uvicorn provenance.app:app` by default, or the deployed service when
`PROVENANCE_SERVICE_URL` is set — the two-mode shape `scripts/verify_incident_one.py` uses.
**Mutates nothing**, needs no token, and can run as many times as you like: that is the whole
posture of the surface it checks. A read spends nothing, which is exactly why `/trigger` is
guarded and this is not.

What it asserts, and why each one is here rather than being obvious:

- **The breakdown multiplies back to the number beside it.** A rendered arithmetic that does
  not reproduce its own total is decoration, and §4.3's defence is that the number is
  computed and inspectable. This is `telemetry.set_risk()`'s components-must-sum rule applied
  to a product instead of a sum.
- **One row per distinct source class.** §4.3 collapses a class to its least-decayed item, so
  a breakdown with a row per evidence *item* would show one dial read three times as three
  corroborating sources — the picture §6.3 exists to stop anyone being shown.
- **Every version's stored confidence recomputes from its own citations at its own commit
  time.** This is the strong form: not just that the current number is honest, but that each
  superseded one still is. It is what "the arithmetic is in the store" means.
- **The chain is whole and the backlink is derived.** `supersedes` is stored on the newer
  version, `superseded_by` is not stored at all (ADR-016) — v1 carries it here only because
  v2 exists.
- **A missing belief is 404 and an unreadable store is 503.** §7.3: "the store was unreadable"
  and "the organization believes nothing" must not look alike. Only the 404 half is checkable
  from outside; the 503 half is `tests/test_app.py`'s.

Needs the belief seeded (`scripts/seed_belief.py`) but no cloud credentials of its own — it
talks HTTP. The offline half is the `/belief/{entity}` block in `tests/test_app.py`.
"""

from __future__ import annotations

import math
import os
import sys
from datetime import UTC, datetime

import httpx

ENTITY = "SUP-042"
DEFAULT_URL = "http://127.0.0.1:8000"
HALF_LIFE_DAYS = 30.0
TIMESTAMP = "%Y-%m-%dT%H:%M:%SZ"

# `commit()` computed each stored number at a `now` carrying microseconds, while
# `committed_at` is truncated to the second. One second against a 30-day half-life is under
# 1e-7; anything above this tolerance is the formula disagreeing with itself, not the clock.
TOLERANCE = 1e-6


class Failed(Exception):
    """A check did not hold."""


def check(condition: bool, message: str) -> None:
    if not condition:
        raise Failed(message)
    print(f"    ok: {message}")


def parse(stamp: str) -> datetime:
    return datetime.strptime(stamp, TIMESTAMP).replace(tzinfo=UTC)


def noisy_or(weights: list[float]) -> float:
    product = 1.0
    for weight in weights:
        product *= 1 - weight
    return 1 - product


def recompute(version: dict, evidence: dict) -> float:
    """§4.3 from first principles, against the version's own citations at its own commit time.

    Deliberately re-implemented here rather than imported from `policy.contributions()`:
    importing the thing under test would make this assert that a function equals itself.
    """
    at = parse(version["committed_at"])
    strongest: dict[str, float] = {}
    for item_id in version["evidence_ids"]:
        item = evidence[item_id]
        age = max(0.0, (at - parse(item["observed_at"])).total_seconds() / 86400)
        base = {
            "verified_system_observation": 0.60,
            "third_party_audit": 0.55,
            "contractual_record": 0.50,
            "agent_inference": 0.15,
            "unverified_external_claim": 0.00,
        }[item["source_class"]]
        weight = base * 2 ** (-age / HALF_LIFE_DAYS)
        strongest[item["source_class"]] = max(strongest.get(item["source_class"], 0.0), weight)
    return noisy_or(list(strongest.values()))


def checks(base_url: str) -> None:
    print(f"==> GET {base_url}/belief/{ENTITY}  (no token, nothing mutated)")
    response = httpx.get(f"{base_url}/belief/{ENTITY}", timeout=30)
    check(
        response.status_code == 200,
        f"the inspector answers a cold request with {response.status_code}",
    )
    body = response.json()

    versions, evidence, current = body["versions"], body["evidence"], body["current"]
    check(body["belief_id"] == f"belief-{ENTITY}", f"belief_id is {body['belief_id']}")
    check(body["scope"] == "ENTITY", f"scope is {body['scope']}")

    print("==> the chain (§3.2's history block, ADR-016's forward-only links)")
    check(len(versions) == 2, f"two versions in the chain, found {len(versions)}")
    v1, v2 = versions
    check(v1["status"] == "FLAGGED" and v2["status"] == "AT_RISK", "FLAGGED superseded by AT_RISK")
    check(v2["supersedes"] == 1, f"v2 stores supersedes={v2['supersedes']}")
    check(v1["superseded_by"] == 2, "v1's backlink was derived from v2 existing, not stored")
    check(v2["superseded_by"] is None, "the newest version is the one in force")
    check(v1["threshold"] == 0.50, "v1 faced the new-belief door at 0.50")
    check(v2["threshold"] == 0.70, "v2 faced the flip door at 0.70")
    # §6.3: a flip needs a source class the chain did not already carry.
    classes = {evidence[i]["source_class"] for i in v1["evidence_ids"]}
    added = {evidence[i]["source_class"] for i in v2["evidence_ids"]} - classes
    check(bool(added), f"the flip rests on a new source class: {sorted(added)}")

    print("==> the arithmetic (§4.3, computed and inspectable)")
    rows = current["breakdown"]
    check(
        len(rows) == len({r["source_class"] for r in rows}),
        f"one row per distinct source class, {len(rows)} rows",
    )
    check(
        len(rows) == len({evidence[i]["source_class"] for i in v2["evidence_ids"]}),
        "every class the version rests on has a row",
    )
    for row in rows:
        expected = row["base"] * 2 ** (-row["age_days"] / HALF_LIFE_DAYS)
        check(
            abs(row["weight"] - expected) < TOLERANCE,
            f"{row['source_class']}: {row['base']:.2f} x 2^(-{row['age_days']:.1f}/30)"
            f" = {row['weight']:.4f}",
        )
    total = noisy_or([row["weight"] for row in rows])
    check(
        abs(total - current["confidence_now"]) < TOLERANCE,
        f"1 - PROD(1 - w) = {total:.4f}, which is the number rendered beside it",
    )

    print("==> every version's stored number still recomputes from its own citations")
    for version in versions:
        again = recompute(version, evidence)
        check(
            abs(again - version["confidence"]) < TOLERANCE,
            f"v{version['version']} stores {version['confidence']:.4f}, recomputes to {again:.4f}",
        )
    check(
        current["confidence_now"] <= v2["confidence"] + TOLERANCE,
        f"age never buys confidence back: {v2['confidence']:.6f} -> "
        f"{current['confidence_now']:.6f}",
    )

    print("==> evidence (§3.3, typed and re-checkable by a third party)")
    check(
        set(evidence) == {i for v in versions for i in v["evidence_ids"]},
        f"every citation resolves, {len(evidence)} items",
    )
    for item in evidence.values():
        check(
            bool(item["verifiable_by"]) and bool(item["payload_hash"]),
            f"{item['id']} ({item['source_class']}) says how to re-check it",
        )

    print("==> the decay clock (§6.5)")
    check(v2["half_life_days"] == HALF_LIFE_DAYS, f"half-life is {v2['half_life_days']}")
    check(v2["on_expiry"] == "REVERIFY", f"on_expiry is {v2['on_expiry']}")
    expected_expiry = parse(v2["committed_at"]).timestamp() + HALF_LIFE_DAYS * 86400
    check(
        math.isclose(parse(v2["expires_at"]).timestamp(), expected_expiry),
        f"expires_at is committed_at + {HALF_LIFE_DAYS:.0f}d: {v2['expires_at']}",
    )
    left = (parse(v2["expires_at"]) - datetime.now(UTC)).days
    print(f"    (clock reads {left}d remaining; the Sweeper that consumes it is item 29)")

    print("==> §7.3: a belief that is not there is not an outage")
    missing = httpx.get(f"{base_url}/belief/nonesuch", timeout=30)
    check(
        missing.status_code == 404,
        f"an unknown entity is {missing.status_code}, and 404 is not 503",
    )


def main() -> int:
    base_url = os.environ.get("PROVENANCE_SERVICE_URL", DEFAULT_URL).rstrip("/")
    where = "deployed" if "PROVENANCE_SERVICE_URL" in os.environ else "local"
    print(f"==> belief inspector, {where}: {base_url}")
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
    print("==> done. The inspector publishes the arithmetic, and it reproduces the number.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
