#!/usr/bin/env python3
"""Inject the incident #1 fault into live Firestore, and take it back out again.

    GOOGLE_CLOUD_PROJECT=provenance-hackathon .venv/bin/python scripts/inject_fault.py
    GOOGLE_CLOUD_PROJECT=provenance-hackathon .venv/bin/python scripts/inject_fault.py --clear

The spec's §13: "`inventory-api` error rate spikes to 38% six minutes after a config deploy."
Two writes make that true of the seeded world -- the observed error rate on the service, and
the `fault_injection/{target_id}` switch ADR-009 put there so a fault is one Firestore write
rather than a redeploy, flippable on camera and readable at request time.

`--clear` restores the baseline (`scripts/seed_firestore.py`'s nominal rate, switch off). Both
directions read back what they wrote and exit non-zero on a mismatch, the same posture every
live script in this repo takes since item 2.

This script does not trigger anything. Waking the fleet is `POST /trigger` (item 9), which is
deliberately a separate step: the fault is a fact about the world, and the trigger is a monitor
noticing it. Item 10 is the first thing that reads the switch back.
"""

from __future__ import annotations

import os
import sys
from typing import Any

from google.cloud import firestore

from provenance.synthetic import company

TARGET = "inventory-api"
SPIKED_ERROR_RATE = 0.38


def baseline() -> tuple[float, dict[str, Any]]:
    """What `seed_firestore.py` wrote, read from the same in-code fixture it wrote from."""
    switch = next(f for f in company.FAULT_SWITCHES if f.target_id == TARGET)
    return company.service(TARGET).error_rate, {
        "error_rate_spike": switch.error_rate_spike,
        "rollback_fails": switch.rollback_fails,
        "verification_ambiguous": switch.verification_ambiguous,
    }


def main() -> int:
    project_id = os.environ.get("GOOGLE_CLOUD_PROJECT")
    if not project_id:
        print("GOOGLE_CLOUD_PROJECT is not set.", file=sys.stderr)
        return 1
    clear = "--clear" in sys.argv[1:]

    nominal, switch_baseline = baseline()
    error_rate = nominal if clear else SPIKED_ERROR_RATE
    spike = not clear

    client = firestore.Client(project=project_id)
    client.collection("services").document(TARGET).update({"error_rate": error_rate})
    client.collection("fault_injection").document(TARGET).update(
        {**switch_baseline, "error_rate_spike": spike}
    )

    service = client.collection("services").document(TARGET).get().to_dict() or {}
    fault = client.collection("fault_injection").document(TARGET).get().to_dict() or {}
    failures = 0
    if service.get("error_rate") != error_rate:
        print(
            f"FAIL: error_rate is {service.get('error_rate')}, expected {error_rate}",
            file=sys.stderr,
        )
        failures += 1
    if fault.get("error_rate_spike") is not spike:
        print(
            f"FAIL: error_rate_spike is {fault.get('error_rate_spike')}, expected {spike}",
            file=sys.stderr,
        )
        failures += 1
    if failures:
        return 1

    verb = "cleared" if clear else "injected"
    print(
        f"--> {verb}: services/{TARGET}.error_rate={error_rate} "
        f"fault_injection/{TARGET}.error_rate_spike={spike}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
