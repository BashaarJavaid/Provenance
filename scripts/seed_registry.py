#!/usr/bin/env python3
"""Write the agent registry to Firestore, generating each agent's keypair exactly once.

    GOOGLE_CLOUD_PROJECT=provenance-hackathon .venv/bin/python scripts/seed_registry.py
    GOOGLE_CLOUD_PROJECT=provenance-hackathon .venv/bin/python scripts/seed_registry.py \
        --rotate sre-infra-agent

Create-if-absent, and unlike `scripts/seed_firestore.py` there is deliberately **no
`--reset`**. ARCHITECTURE.md §3.4: restoration of standing "requires explicit human
reinstatement; the system never quietly forgives". A re-run that rewrote the fixture's
`standing: GOOD` over a stored DEGRADED would be exactly that quiet forgiveness, in a
script an operator runs without thinking. So an existing `agents/{id}` is skipped whole —
standing and `rejection_window` survive every re-run, and `registry.set_standing()` is the
only thing that ever changes standing.

Skipping whole also means a keypair is generated once per agent, on first seed: rotating
on every run would invalidate any credential item 7 had minted. `--rotate <agent-id>` is
the one deliberate path to a new key; it bumps the version and leaves standing alone.

The private key is printed once, here, and never written to disk or committed. Item 7
decides how a signing agent receives it (env var, Secret Manager); this item does not
invent a key store it would then have to defend.

Not run in CI: CI has no credentials. The offline half is `tests/test_registry.py`.
"""

from __future__ import annotations

import os
import re
import sys
from dataclasses import replace
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from google.cloud import firestore

from provenance import registry


def generate_keypair() -> tuple[str, str]:
    """A P-256 keypair as (public PEM, private PEM). Item 7 verifies against the public half."""
    private = ec.generate_private_key(ec.SECP256R1())
    public_pem = (
        private.public_key()
        .public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        .decode()
    )
    private_pem = private.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode()
    return public_pem, private_pem


def next_version(version: str) -> str:
    """`v1` -> `v2`. A rotated key is a different identity, so it gets a different version."""
    match = re.fullmatch(r"v(\d+)", version)
    if not match:
        raise ValueError(f"cannot bump a non-numeric version: {version!r}")
    return f"v{int(match.group(1)) + 1}"


def print_private_key(agent_id: str, private_pem: str) -> None:
    print(f"    private key for {agent_id} — store it now, it is not shown again:")
    for line in private_pem.strip().splitlines():
        print(f"      {line}")


def seed(client: firestore.Client, rotate: str | None) -> list[tuple[str, dict[str, Any]]]:
    """Write the records that need writing. Returns (agent_id, payload) for each one."""
    written: list[tuple[str, dict[str, Any]]] = []
    for agent in registry.AGENTS:
        ref = client.collection(registry.COLLECTION).document(agent.id)
        snapshot = ref.get()

        if snapshot.exists and agent.id != rotate:
            print(f"    exists   {registry.COLLECTION}/{agent.id}")
            continue

        public_pem, private_pem = generate_keypair()
        if snapshot.exists:
            # Rotating: keep whatever standing and rejection history the record has earned.
            stored = registry.from_document(agent.id, snapshot.to_dict())
            record = replace(stored, public_key=public_pem, version=next_version(stored.version))
            label = f"rotated  {registry.COLLECTION}/{agent.id} -> {record.version}"
        else:
            record = replace(agent, public_key=public_pem)
            label = f"written  {registry.COLLECTION}/{agent.id}"

        payload = registry.to_document(record)
        ref.set(payload)
        written.append((agent.id, payload))
        print(f"    {label}")
        print_private_key(agent.id, private_pem)
    return written


def read_back(client: firestore.Client, written: list[tuple[str, dict[str, Any]]]) -> list[str]:
    """Re-read every record; return the ids that fail their check.

    Every fixture agent must exist -- that is the seed's claim. Content is compared only
    for records this run wrote, for the same reason seed_firestore.py does it that way: a
    record skipped as already present may legitimately carry a DEGRADED standing this
    fixture knows nothing about, and that is the system working, not a seeding fault.
    """
    written_payloads = dict(written)
    failed: list[str] = []
    for agent in registry.AGENTS:
        snapshot = client.collection(registry.COLLECTION).document(agent.id).get()
        if not snapshot.exists:
            failed.append(f"{agent.id} (absent)")
        elif agent.id in written_payloads and snapshot.to_dict() != written_payloads[agent.id]:
            failed.append(f"{agent.id} (written, but differs from what was sent)")
        else:
            # Parsing is part of the check: a record the read API cannot parse is not seeded.
            try:
                registry.from_document(agent.id, snapshot.to_dict())
            except registry.RegistryError as exc:
                failed.append(f"{agent.id} ({exc})")
    return failed


def main() -> int:
    project_id = os.environ.get("GOOGLE_CLOUD_PROJECT")
    if not project_id:
        print("FAIL: GOOGLE_CLOUD_PROJECT is not set.", file=sys.stderr)
        print("      Re-run with:", file=sys.stderr)
        print(
            "        GOOGLE_CLOUD_PROJECT=provenance-hackathon"
            " .venv/bin/python scripts/seed_registry.py",
            file=sys.stderr,
        )
        return 1

    args = sys.argv[1:]
    rotate: str | None = None
    if "--rotate" in args:
        index = args.index("--rotate")
        if index + 1 >= len(args):
            print("FAIL: --rotate needs an agent id.", file=sys.stderr)
            return 1
        rotate = args[index + 1]
        if rotate not in {agent.id for agent in registry.AGENTS}:
            print(f"FAIL: {rotate!r} is not a registered agent.", file=sys.stderr)
            return 1

    print(f"==> agent registry -> {project_id}   ({len(registry.AGENTS)} agents)")
    if rotate:
        print(f"--> --rotate: {rotate} gets a new keypair and a bumped version")

    client = firestore.Client(project=project_id)
    written = seed(client, rotate)
    print(f"--> {len(written)} written, {len(registry.AGENTS) - len(written)} already present")

    print("--> reading every record back")
    failed = read_back(client, written)
    if failed:
        print(f"FAIL: {len(failed)} record(s) did not verify: {failed}", file=sys.stderr)
        return 1

    print(f"==> done. {len(registry.AGENTS)} present, {len(written)} content-verified.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
