#!/usr/bin/env python3
"""Inject the incident #1 fault into live Firestore, and take it back out again.

    GOOGLE_CLOUD_PROJECT=provenance-hackathon .venv/bin/python scripts/inject_fault.py
    GOOGLE_CLOUD_PROJECT=provenance-hackathon .venv/bin/python scripts/inject_fault.py --clear
    GOOGLE_CLOUD_PROJECT=provenance-hackathon .venv/bin/python scripts/inject_fault.py \
        --rollback-fails

The spec's §13: "`inventory-api` error rate spikes to 38% six minutes after a config deploy."
Two writes make that true of the seeded world -- the observed error rate on the service, and
the `fault_injection/{target_id}` switch ADR-009 put there so a fault is one Firestore write
rather than a redeploy, flippable on camera and readable at request time.

`--clear` restores the baseline (`scripts/seed_firestore.py`'s nominal rate, every switch off).
Both directions read back what they wrote and exit non-zero on a mismatch, the same posture
every live script in this repo takes since item 2.

Item 19 added the other two §9 switches, and they are set **alongside** the spike rather than
instead of it -- `--rollback-fails` needs a deviation for the fleet to respond to before it can
demonstrate a remediation that does not clear it, and so does `--ambiguous`. Every write goes
through `baseline()`, so a flag left off is written off rather than left at whatever the last
run set: two switches on at once is a state neither beat means and nothing would clear it.

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

# §9's other two switches (item 19). `error_rate_spike` is deliberately not here: it is what
# every injection sets, not something a flag opts into.
SWITCH_FOR = {"--rollback-fails": "rollback_fails", "--ambiguous": "verification_ambiguous"}


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
    flags = sys.argv[1:]
    unknown = [f for f in flags if f not in SWITCH_FOR and f != "--clear"]
    if unknown:
        print(f"unknown flag(s): {' '.join(unknown)}", file=sys.stderr)
        return 1
    clear = "--clear" in flags

    nominal, switch_baseline = baseline()
    error_rate = nominal if clear else SPIKED_ERROR_RATE
    spike = not clear
    # The baseline first, so an unnamed switch is written *off* rather than left as the last
    # run set it. Both extra switches ride alongside the spike: neither beat is reachable
    # without a deviation for the fleet to respond to in the first place.
    switches = {**switch_baseline, "error_rate_spike": spike}
    if not clear:
        for flag, name in SWITCH_FOR.items():
            switches[name] = flag in flags

    client = firestore.Client(project=project_id)
    client.collection("services").document(TARGET).update({"error_rate": error_rate})
    client.collection("fault_injection").document(TARGET).update(switches)

    service = client.collection("services").document(TARGET).get().to_dict() or {}
    fault = client.collection("fault_injection").document(TARGET).get().to_dict() or {}
    failures = 0
    if service.get("error_rate") != error_rate:
        print(
            f"FAIL: error_rate is {service.get('error_rate')}, expected {error_rate}",
            file=sys.stderr,
        )
        failures += 1
    for name, expected in switches.items():
        if fault.get(name) is not expected:
            print(
                f"FAIL: {name} is {fault.get(name)}, expected {expected}",
                file=sys.stderr,
            )
            failures += 1
    if failures:
        return 1

    verb = "cleared" if clear else "injected"
    on = " ".join(f"{name}={value}" for name, value in switches.items())
    print(f"--> {verb}: services/{TARGET}.error_rate={error_rate} fault_injection/{TARGET}: {on}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
