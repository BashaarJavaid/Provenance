"""The offline half of ROADMAP item 4: the synthetic company's invariants, no credentials.

The live half is `scripts/seed_firestore.py`, which writes the fixture to Firestore and
reads every document back. These tests guard the properties that later items' frozen
numbers and demo beats depend on, so breaking one fails the build here rather than in
Phase 3. Nothing in this file reaches a cloud service.
"""

from __future__ import annotations

from dataclasses import fields
from typing import get_args

import pytest

from provenance.synthetic import company
from provenance.telemetry import TargetKind

TIERS = {"tier1", "tier2", "tier3"}

SERVICES_BY_ID = {service.id: service for service in company.SERVICES}
SUPPLIERS_BY_ID = {supplier.id: supplier for supplier in company.SUPPLIERS}


def test_the_two_tiers_the_frozen_risk_scores_depend_on() -> None:
    # ARCHITECTURE §4.2 scores ROLLBACK_CONFIG(inventory-api) at 2 (criticality +1, tier2)
    # and DISABLE_COMPLIANCE_CHECKS(SUP-042) at 11 (criticality +2, tier1). Item 7 asserts
    # both totals exactly, and its only route to `criticality` is this entity model.
    assert SERVICES_BY_ID["inventory-api"].tier == "tier2"
    assert SUPPLIERS_BY_ID["SUP-042"].tier == "tier1"


def test_every_tier_is_in_the_vocabulary() -> None:
    for entity in (*company.SERVICES, *company.SUPPLIERS):
        assert entity.tier in TIERS, entity.id


def test_target_ids_are_unique_across_the_entity_model() -> None:
    # §3.1: a typed Action's `target` is one id looked up against the whole entity model,
    # so a service and a supplier may not share one.
    ids = [service.id for service in company.SERVICES] + [s.id for s in company.SUPPLIERS]
    assert len(ids) == len(set(ids))


def test_inventory_api_has_a_rollback_target() -> None:
    inventory = SERVICES_BY_ID["inventory-api"]
    versions = [v for v in company.CONFIG_VERSIONS if v.service_id == "inventory-api"]
    known_good = [v for v in versions if v.known_good]

    assert len(known_good) == 1, "exactly one version is the rollback target"
    assert known_good[0].version == "v41"
    assert inventory.known_good_version == "v41"
    # v42 deployed over a good v41 is the precondition incident #1 needs: without the gap
    # there is nothing for ROLLBACK_CONFIG(v42 -> v41) to do.
    assert inventory.current_config_version == "v42"
    assert inventory.current_config_version != inventory.known_good_version


def test_pricing_api_has_no_deploy_history() -> None:
    # Incident #3's whole point is an entity the fleet has never handled (§13, item 24).
    # A config history here would give the domain agent something to reason from and the
    # class belief would no longer be carrying the diagnosis.
    assert SERVICES_BY_ID["pricing-api"].current_config_version is None
    assert [v for v in company.CONFIG_VERSIONS if v.service_id == "pricing-api"] == []


def test_two_tier2_services_beyond_the_sre_arc() -> None:
    # §9: "two additional tier-2 services that never appear in an incident" — pricing-api
    # is one of them, which is what makes incident #3 land on a member of that population.
    extra = [s for s in company.SERVICES if s.id != "inventory-api"]
    assert len(extra) == 2
    assert all(s.tier == "tier2" for s in extra)
    assert "pricing-api" in {s.id for s in extra}


def test_every_service_has_a_fault_switch_and_all_are_off_at_baseline() -> None:
    switched = {switch.target_id for switch in company.FAULT_SWITCHES}
    assert switched == set(SERVICES_BY_ID)
    for switch in company.FAULT_SWITCHES:
        assert not switch.error_rate_spike
        assert not switch.rollback_fails
        assert not switch.verification_ambiguous


@pytest.mark.parametrize("cls", [company.Service, company.Supplier])
def test_entities_carry_no_belief_like_status(cls: type) -> None:
    # §2.2: status is something the Memory Policy Engine commits, never something a seed
    # asserts. SUP-042 being AT_RISK is a belief (item 17) with evidence and a computed
    # confidence behind it; a `status` field here would be that claim without either.
    names = {field.name for field in fields(cls)}
    assert not names & {"status", "belief", "confidence", "at_risk"}


def test_the_approver_is_the_non_technical_persona() -> None:
    assert company.APPROVER.role == "Store Operations Manager"
    assert company.APPROVER.non_technical is True


def test_the_retail_base_is_internally_consistent() -> None:
    # Recurrence is the point (§9): every order resolves to a seeded customer and product,
    # and every product to a seeded supplier.
    skus = {product.sku for product in company.PRODUCTS}
    customers = {customer.id for customer in company.CUSTOMERS}
    for order in company.ORDERS:
        assert order.customer_id in customers, order.id
        assert order.sku in skus, order.id
    for product in company.PRODUCTS:
        assert product.supplier_id in SUPPLIERS_BY_ID, product.sku


def test_the_entity_lookups_resolve_and_raise_on_a_miss() -> None:
    # §3.1's "target must exist in the entity model", as one call per kind. Item 6's validator
    # turns the KeyError into UnknownTarget; items 7, 9 and 10 read the tier off the result.
    assert company.service("inventory-api").tier == "tier2"
    assert company.supplier("SUP-042").tier == "tier1"
    with pytest.raises(KeyError):
        company.service("billing-api")
    with pytest.raises(KeyError):
        company.supplier("SUP-999")
    # Kinds do not bleed: a supplier id is not a service, which is what makes the tool schema's
    # `target_kind` load-bearing rather than decorative.
    with pytest.raises(KeyError):
        company.service("SUP-042")


def test_described_resolves_either_kind_and_raises_on_a_miss() -> None:
    """Item 21's one polymorphic read, for the callers that run before a kind is known."""
    for service in company.SERVICES:
        found = company.described(service.id)
        assert (found.kind, found.tier, found.description) == (
            "service",
            service.tier,
            service.description,
        )
    for supplier in company.SUPPLIERS:
        found = company.described(supplier.id)
        assert found.kind == "supplier"
        assert found.tier == supplier.tier
        # Composed from the fields §9 already gives a supplier, never a stored `description`:
        # a field the seeder writes and nothing checks is a field that drifts.
        assert supplier.name in found.description
        assert supplier.category in found.description
        assert supplier.contract_ref in found.description
    with pytest.raises(KeyError):
        company.described("billing-api")


def test_described_agrees_with_the_tool_registry_vocabulary() -> None:
    """The kind it returns is the one `tools.Tool.target_kind` selects a collection with."""
    kinds = {company.described(e.id).kind for e in (*company.SERVICES, *company.SUPPLIERS)}
    assert kinds == set(get_args(TargetKind))
