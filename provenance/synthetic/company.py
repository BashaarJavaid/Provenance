"""The synthetic company — the cast every later incident recurs over (ROADMAP item 4).

`ARCHITECTURE.md` §9: no real company data. The base entity model is adapted from the
`google/adk-samples` Customer Service sample (Apache-2.0) — a fictional big-box
home-improvement/gardening retailer with a customer/order/inventory model. Nothing is
vendored or fetched; the shape is reproduced here by hand. Everything below the retail
base — services, config versions, suppliers, the fault switch, the approver — is authored
for this project, which is exactly what the `README.md` disclosure table claims.

Two invariants here are load-bearing for numbers frozen elsewhere and are asserted by
`tests/test_synthetic_company.py`:

  * `inventory-api` is **tier2** and `SUP-042` is **tier1**. §4.2's worked examples score
    `ROLLBACK_CONFIG(inventory-api)` at 2 and `DISABLE_COMPLIANCE_CHECKS(SUP-042)` at 11
    via `criticality_points[target_tier]`; change either tier and item 7's tests break.
  * No service or supplier carries a status. Status is something the Memory Policy Engine
    commits as a belief (§2.2) — `SUP-042`'s AT_RISK belief is item 17's job, not a field
    a seed script gets to assert.

`scripts/seed_firestore.py` writes all of this to Firestore. This module holds no cloud
imports so the invariants can be checked in CI with no credentials.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

COMPANY_NAME = "Cymbal Home & Garden"

Tier = Literal["tier1", "tier2", "tier3"]


@dataclass(frozen=True)
class Service:
    """A service in the entity model. §3.1's typed Action validates `target` against these."""

    id: str
    name: str
    tier: Tier
    domain: str
    description: str
    # Mutable synthetic state. Item 9 spikes `error_rate` and item 10 rolls
    # `current_config_version` back; both fields exist now so neither item invents a shape.
    # None on a service with no deploy history.
    current_config_version: str | None
    known_good_version: str | None
    error_rate: float
    healthy: bool


@dataclass(frozen=True)
class ConfigVersion:
    """One deploy of one service, stored under `services/{id}/config_versions/{version}`."""

    service_id: str
    version: str
    deployed_at: str
    known_good: bool
    summary: str
    params: dict[str, int]


@dataclass(frozen=True)
class Supplier:
    id: str
    name: str
    tier: Tier
    category: str
    contract_ref: str
    onboarded_at: str


@dataclass(frozen=True)
class FaultSwitch:
    """The §9 fault-injection switch: data, read at request time, not deploy config.

    All three are False at baseline. Phase 3 flips `error_rate_spike` to start incident #1;
    item 19 flips `rollback_fails` so verification genuinely returns REFUTED, and
    `verification_ambiguous` so it genuinely returns INCONCLUSIVE.
    """

    target_id: str
    error_rate_spike: bool
    rollback_fails: bool
    verification_ambiguous: bool


@dataclass(frozen=True)
class Approver:
    """§9's named human approver — the 'Unlikely Hero' who owns the item-30 queue."""

    id: str
    name: str
    role: str
    non_technical: bool


@dataclass(frozen=True)
class Customer:
    id: str
    name: str
    email: str
    city: str
    member_since: str


@dataclass(frozen=True)
class Product:
    sku: str
    name: str
    category: str
    unit_price_cents: int
    supplier_id: str


@dataclass(frozen=True)
class Order:
    id: str
    customer_id: str
    sku: str
    quantity: int
    placed_at: str
    fulfillment: str


SERVICES: tuple[Service, ...] = (
    # The SRE arc (incidents #1 and #2). v42 is deployed and v41 is the known-good state to
    # roll back to — that gap is the precondition incident #1 needs to exist at all.
    Service(
        id="inventory-api",
        name="Inventory API",
        tier="tier2",
        domain="sre",
        description="Stock levels and reservations for store and online fulfillment.",
        current_config_version="v42",
        known_good_version="v41",
        error_rate=0.01,
        healthy=True,
    ),
    # Incident #3's subject. Deliberately has no config history and will have no entity
    # beliefs: the §6.2 class belief has to carry the whole diagnosis on a service the
    # fleet has never handled. Give it a deploy history and the beat proves nothing.
    Service(
        id="pricing-api",
        name="Pricing API",
        tier="tier2",
        domain="sre",
        description="Promotional and markdown pricing for the storefront.",
        current_config_version=None,
        known_good_version=None,
        error_rate=0.01,
        healthy=True,
    ),
    # Never appears in any incident. It exists so the class belief's "tier-2 services"
    # population is larger than the two services the demo actually touches.
    Service(
        id="checkout-api",
        name="Checkout API",
        tier="tier2",
        domain="sre",
        description="Cart totals, payment authorization handoff, and order creation.",
        current_config_version=None,
        known_good_version=None,
        error_rate=0.01,
        healthy=True,
    ),
)

CONFIG_VERSIONS: tuple[ConfigVersion, ...] = (
    ConfigVersion(
        service_id="inventory-api",
        version="v41",
        deployed_at="2026-08-14T09:12:00Z",
        known_good=True,
        summary="Steady state. Connection pool sized for peak weekend load.",
        params={"connection_pool_max": 80, "request_timeout_ms": 2000, "retry_max": 2},
    ),
    ConfigVersion(
        service_id="inventory-api",
        version="v42",
        deployed_at="2026-08-21T15:41:00Z",
        known_good=False,
        summary="Connection pool reduced to cut idle database cost.",
        params={"connection_pool_max": 20, "request_timeout_ms": 2000, "retry_max": 2},
    ),
)

SUPPLIERS: tuple[Supplier, ...] = (
    # "Supplier X". tier1 because §4.2 scores DISABLE_COMPLIANCE_CHECKS(SUP-042) with
    # criticality +2. Carries no status field — AT_RISK is a belief (item 17).
    Supplier(
        id="SUP-042",
        name="Verdant Supply Co.",
        tier="tier1",
        category="live_goods",
        contract_ref="CTR-2024-0042",
        onboarded_at="2024-03-11",
    ),
    Supplier(
        id="SUP-017",
        name="Northgate Timber",
        tier="tier2",
        category="lumber",
        contract_ref="CTR-2023-0017",
        onboarded_at="2023-06-02",
    ),
    Supplier(
        id="SUP-093",
        name="Bramble Nurseries",
        tier="tier2",
        category="live_goods",
        contract_ref="CTR-2025-0093",
        onboarded_at="2025-01-20",
    ),
)

FAULT_SWITCHES: tuple[FaultSwitch, ...] = tuple(
    FaultSwitch(
        target_id=service.id,
        error_rate_spike=False,
        rollback_fails=False,
        verification_ambiguous=False,
    )
    for service in SERVICES
)

APPROVER = Approver(
    id="dana-ruiz",
    name="Dana Ruiz",
    role="Store Operations Manager",
    non_technical=True,
)

CUSTOMERS: tuple[Customer, ...] = (
    Customer(
        id="CUS-1041",
        name="Priya Raman",
        email="priya.raman@example.com",
        city="Sacramento",
        member_since="2021-04-18",
    ),
    Customer(
        id="CUS-1188",
        name="Marcus Bell",
        email="marcus.bell@example.com",
        city="Fresno",
        member_since="2023-09-02",
    ),
    Customer(
        id="CUS-1276",
        name="Ana Oyelaran",
        email="ana.oyelaran@example.com",
        city="Modesto",
        member_since="2025-02-27",
    ),
)

PRODUCTS: tuple[Product, ...] = (
    Product(
        sku="SKU-7781",
        name="Japanese Maple, 5 gal",
        category="trees",
        unit_price_cents=8999,
        supplier_id="SUP-042",
    ),
    Product(
        sku="SKU-7794",
        name="Lavender 'Hidcote', 1 gal",
        category="perennials",
        unit_price_cents=1499,
        supplier_id="SUP-042",
    ),
    Product(
        sku="SKU-3320",
        name="Cedar Fence Picket, 6 ft",
        category="lumber",
        unit_price_cents=799,
        supplier_id="SUP-017",
    ),
    Product(
        sku="SKU-3361",
        name="Pressure-Treated Post, 4x4x8",
        category="lumber",
        unit_price_cents=1899,
        supplier_id="SUP-017",
    ),
    Product(
        sku="SKU-5102",
        name="Boston Fern, 10 in hanging",
        category="houseplants",
        unit_price_cents=2499,
        supplier_id="SUP-093",
    ),
    Product(
        sku="SKU-5140",
        name="Raised Bed Soil, 2 cu ft",
        category="soil",
        unit_price_cents=1299,
        supplier_id="SUP-093",
    ),
)

ORDERS: tuple[Order, ...] = (
    Order(
        id="ORD-90114",
        customer_id="CUS-1041",
        sku="SKU-7781",
        quantity=1,
        placed_at="2026-08-18T17:22:00Z",
        fulfillment="delivered",
    ),
    Order(
        id="ORD-90152",
        customer_id="CUS-1041",
        sku="SKU-5140",
        quantity=4,
        placed_at="2026-08-19T11:05:00Z",
        fulfillment="delivered",
    ),
    Order(
        id="ORD-90233",
        customer_id="CUS-1188",
        sku="SKU-3320",
        quantity=24,
        placed_at="2026-08-20T08:47:00Z",
        fulfillment="in_transit",
    ),
    Order(
        id="ORD-90287",
        customer_id="CUS-1276",
        sku="SKU-7794",
        quantity=6,
        placed_at="2026-08-20T19:30:00Z",
        fulfillment="picking",
    ),
    Order(
        id="ORD-90301",
        customer_id="CUS-1276",
        sku="SKU-5102",
        quantity=2,
        placed_at="2026-08-21T10:14:00Z",
        fulfillment="picking",
    ),
)

# --- entity lookup ----------------------------------------------------------------------
#
# §3.1's "target must exist in the entity model" needs one call per entity kind. ADR-009 kept
# the collections typed precisely so the caller always knows which kind it holds, and item 6's
# tool schema names that kind (`tools.Tool.target_kind`), so a polymorphic lookup would have
# nothing to resolve. Both raise `KeyError`; nothing here returns an optional.

_SERVICES_BY_ID = {service.id: service for service in SERVICES}
_SUPPLIERS_BY_ID = {supplier.id: supplier for supplier in SUPPLIERS}


def service(service_id: str) -> Service:
    """The service with this id. Raises `KeyError` if the entity model has no such service."""
    return _SERVICES_BY_ID[service_id]


def supplier(supplier_id: str) -> Supplier:
    """The supplier with this id. Raises `KeyError` if the entity model has no such supplier."""
    return _SUPPLIERS_BY_ID[supplier_id]
