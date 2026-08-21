#!/usr/bin/env python3
"""Write the synthetic company to Firestore and read every document back. ROADMAP item 4's
`verify:` line -- "a seed script populates Firestore idempotently" -- checked by the API
rather than by eye, the way item 2 reads its trace back and item 3 curls /health.

    GOOGLE_CLOUD_PROJECT=provenance-hackathon .venv/bin/python scripts/seed_firestore.py
    GOOGLE_CLOUD_PROJECT=provenance-hackathon .venv/bin/python scripts/seed_firestore.py --reset

Default is create-if-absent: a re-run reports every document as already present and
changes nothing. `--reset` rewrites every document the fixture owns, restoring the demo
baseline -- v42 deployed over a good v41, nominal error rates, every fault switch off.
That is the between-takes reset for the item-37 rehearsal.

Nothing outside `provenance/synthetic/company.py` is ever read or written. The `beliefs`,
`evidence` and `agents` collections belong to the Memory Policy Engine and the registry;
a seed script asserting a belief would be exactly the write path ARCHITECTURE §2.2 exists
to prevent.

Not run in CI: CI has no credentials. The offline half is `tests/test_synthetic_company.py`.
"""

from __future__ import annotations

import os
import sys
from dataclasses import asdict
from typing import Any

from google.cloud import firestore

from provenance.synthetic import company

# (collection, document id, payload) for every document the fixture owns. Subcollection
# documents carry their parent path in `collection` as "services/{id}/config_versions".
Document = tuple[str, str, dict[str, Any]]


def documents() -> list[Document]:
    docs: list[Document] = [
        ("services", service.id, asdict(service)) for service in company.SERVICES
    ]
    docs += [
        (f"services/{cv.service_id}/config_versions", cv.version, asdict(cv))
        for cv in company.CONFIG_VERSIONS
    ]
    docs += [("suppliers", s.id, asdict(s)) for s in company.SUPPLIERS]
    docs += [("fault_injection", f.target_id, asdict(f)) for f in company.FAULT_SWITCHES]
    docs += [("approvers", company.APPROVER.id, asdict(company.APPROVER))]
    docs += [("customers", c.id, asdict(c)) for c in company.CUSTOMERS]
    docs += [("products", p.sku, asdict(p)) for p in company.PRODUCTS]
    docs += [("orders", o.id, asdict(o)) for o in company.ORDERS]
    return docs


def write(client: firestore.Client, docs: list[Document], reset: bool) -> list[Document]:
    """Write each document, skipping ones that already exist unless resetting.

    Returns the documents this run actually wrote -- the only ones whose *content* this
    run is entitled to assert anything about.
    """
    written: list[Document] = []
    for doc in docs:
        collection, doc_id, payload = doc
        ref = client.collection(collection).document(doc_id)
        if not reset and ref.get().exists:
            print(f"    exists   {collection}/{doc_id}")
            continue
        ref.set(payload)
        written.append(doc)
        print(f"    {'reset  ' if reset else 'written'}  {collection}/{doc_id}")
    return written


def read_back(client: firestore.Client, docs: list[Document], written: list[Document]) -> list[str]:
    """Re-read every document; return the paths that fail their check.

    Every document must exist -- that is the seed's actual claim, "the company is present".
    Content is only compared for documents this run wrote. A document skipped as already
    present may legitimately have drifted from the fixture: mid-rehearsal, `inventory-api`
    is rolled back to v41 with its error rate spiked, which is the demo working, not a
    seeding fault. `--reset` is what restores the baseline, and it rewrites everything, so
    its read-back checks every document's content.
    """
    written_paths = {(collection, doc_id) for collection, doc_id, _ in written}
    failed: list[str] = []
    for collection, doc_id, payload in docs:
        snapshot = client.collection(collection).document(doc_id).get()
        if not snapshot.exists:
            failed.append(f"{collection}/{doc_id} (absent)")
        elif (collection, doc_id) in written_paths and snapshot.to_dict() != payload:
            failed.append(f"{collection}/{doc_id} (written, but differs from the fixture)")
    return failed


def main() -> int:
    project_id = os.environ.get("GOOGLE_CLOUD_PROJECT")
    if not project_id:
        print("FAIL: GOOGLE_CLOUD_PROJECT is not set.", file=sys.stderr)
        print("      Re-run with:", file=sys.stderr)
        print(
            "        GOOGLE_CLOUD_PROJECT=provenance-hackathon"
            " .venv/bin/python scripts/seed_firestore.py",
            file=sys.stderr,
        )
        return 1

    reset = "--reset" in sys.argv[1:]
    docs = documents()
    print(f"==> {company.COMPANY_NAME} -> {project_id}   ({len(docs)} documents)")
    if reset:
        print("--> --reset: rewriting every document to the demo baseline")

    client = firestore.Client(project=project_id)
    written = write(client, docs, reset)
    print(f"--> {len(written)} written, {len(docs) - len(written)} already present")

    print("--> reading every document back")
    failed = read_back(client, docs, written)
    if failed:
        print(f"FAIL: {len(failed)} document(s) did not verify: {failed}", file=sys.stderr)
        return 1

    print(f"==> done. {len(docs)} present, {len(written)} content-verified against the fixture.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
