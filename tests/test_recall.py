"""The offline half of ROADMAP item 16: the index nominates, the store decides.

The verify line is ARCHITECTURE §10's recall row -- "seed a RETRACTED belief whose statement
is the closest embedding match; assert it is never handed to the Orchestrator" -- and
`test_the_closest_match_is_retracted_and_never_handed_over` is that line, twice: once for
`RETRACTED` and once for §6.5's `UNKNOWN(stale)`.

The embedder is injected, so nothing here touches Vertex. That is not only about speed: with
a real embedder the test's premise ("this one is the closest match") would depend on a model's
opinion, and a run where the retracted belief happened *not* to rank first would pass while
proving nothing. Hand-picked vectors make the premise a fact. `scripts/verify_recall.py` is
where a real embedding model has to agree, and it asserts the ranking before it asserts the
drop for exactly this reason.
"""

from __future__ import annotations

import asyncio
import inspect
import types
from typing import Any, Union, get_args, get_origin, get_type_hints

import pytest
from google.api_core.exceptions import ServiceUnavailable
from test_beliefs import a_version, an_evidence
from test_registry import FakeFirestore

from provenance import beliefs, recall

ENTITY = "inventory-api"
QUERY = recall.query_text(
    target=ENTITY,
    signal="error_rate_spike",
    kind="service",
    tier="tier2",
    description="inventory availability and reservation API",
    observed_value=0.38,
)

# Hand-picked so the ranking is a fact about the fixture and not about a model. The query is
# the first vector; `CLOSE` is nearer to it than `FAR`, and `MISS` is orthogonal to it, which
# is what puts `MISS` under SIMILARITY_FLOOR no matter how the constant is later tuned.
QUERY_VEC = (1.0, 0.0, 0.0)
CLOSE = (0.99, 0.14, 0.0)
FAR = (0.80, 0.60, 0.0)
MISS = (0.0, 0.0, 1.0)


def a_class_version(belief_id: str, statement: str, **overrides: Any) -> beliefs.BeliefVersion:
    return a_version(
        overrides.pop("version", 1),
        belief_id=belief_id,
        scope="CLASS",
        entity="service.config_deploy",
        statement=statement,
        **overrides,
    )


def store_with(*versions: beliefs.BeliefVersion) -> FakeFirestore:
    store = FakeFirestore({})
    for version in versions:
        asyncio.run(
            beliefs.append(version, (an_evidence(f"ev-{version.belief_id}"),), client=store)
        )
    return store


def embedder(vectors: dict[str, tuple[float, ...]]) -> recall.Embedder:
    """Return the query vector first, then one per statement, in the order asked."""

    async def embed(texts: Any) -> tuple[tuple[float, ...], ...]:
        return tuple(QUERY_VEC if text == QUERY else vectors[text] for text in texts)

    return embed


# --- the verify line ------------------------------------------------------------------------


@pytest.mark.parametrize("dropped_status", ["RETRACTED", "UNKNOWN"])
def test_the_closest_match_is_retracted_and_never_handed_over(dropped_status: str) -> None:
    # ROADMAP item 16's verify line. The belief the index likes best is the one the store
    # refuses to hand over, and both halves are asserted: without the first the test proves
    # only that an unrelated belief was absent.
    store = store_with(
        a_class_version("belief-class-poolsize", "pool size changes break tier-2 services"),
        a_class_version("belief-class-poolsize", "", version=2, status=dropped_status),
        a_class_version("belief-class-config-deploy", "config deploys correlate with errors"),
    )
    embed = embedder(
        {
            "pool size changes break tier-2 services": CLOSE,
            "config deploys correlate with errors": FAR,
        }
    )

    nominated = asyncio.run(recall.nominate(QUERY, client=store, embed=embed))
    assert nominated[0] == "belief-class-poolsize", "the dropped belief must rank first"

    recalled = asyncio.run(recall.recall(ENTITY, QUERY, client=store, embed=embed))
    assert recalled.nominated_ids[0] == "belief-class-poolsize"
    assert "belief-class-poolsize" not in recalled.belief_ids
    assert [b.belief_id for b in recalled.class_beliefs] == ["belief-class-config-deploy"]
    assert "belief-class-poolsize" not in recalled.summary()


# --- the index ------------------------------------------------------------------------------


def test_the_index_reads_root_documents_and_never_a_version() -> None:
    # ADR-005's "the index never sees confidence, status, or currency", made structural: the
    # roots are present, every *version* subcollection is emptied, and nomination still works.
    # If `nominate()` ever resolved a version to read its statement, this raises rather than
    # quietly ranking nothing.
    store = store_with(
        a_class_version("belief-class-config-deploy", "config deploys correlate with errors")
    )
    for name in [key for key in store.collections if "/versions" in key]:
        store.collections[name] = {}

    embed = embedder({"config deploys correlate with errors": CLOSE})
    assert asyncio.run(recall.nominate(QUERY, client=store, embed=embed)) == (
        "belief-class-config-deploy",
    )


def test_an_entity_belief_is_never_in_the_index() -> None:
    # §6.1 is exact key and §3.2 gives an ENTITY belief no statement. Embedding one at its
    # empty string would put every entity belief in the index at whatever the empty string
    # happens to score against the query.
    store = store_with(a_version(1))
    assert asyncio.run(beliefs.class_statements(client=store)) == ()
    assert asyncio.run(recall.nominate(QUERY, client=store, embed=embedder({}))) == ()


def test_nothing_similar_enough_is_nominated() -> None:
    # The floor is what stops an unrelated incident from dragging in whatever class belief
    # happens to exist. Remove it and this returns the one belief in the store.
    store = store_with(a_class_version("belief-class-supplier", "suppliers miss delivery dates"))
    embed = embedder({"suppliers miss delivery dates": MISS})
    assert asyncio.run(recall.nominate(QUERY, client=store, embed=embed)) == ()


def test_the_index_nominates_at_most_k_best_first() -> None:
    store = store_with(
        *[
            a_class_version(f"belief-class-{n}", f"statement {n}")
            for n in range(recall.NOMINATE_K + 2)
        ]
    )
    # Descending similarity, all above the floor: statement 0 is closest.
    embed = embedder({f"statement {n}": (1.0, 0.02 * n, 0.0) for n in range(recall.NOMINATE_K + 2)})
    nominated = asyncio.run(recall.nominate(QUERY, client=store, embed=embed))
    assert len(nominated) == recall.NOMINATE_K
    assert nominated == tuple(f"belief-class-{n}" for n in range(recall.NOMINATE_K))


# --- fail-closed (§7.3) ---------------------------------------------------------------------


def test_an_unreachable_index_costs_the_class_beliefs_and_nothing_else() -> None:
    # §6.1 promises a mechanical read. An embedding failure must not take it down, and must
    # nominate nothing rather than everything.
    store = store_with(
        a_version(1),
        a_class_version("belief-class-config-deploy", "config deploys correlate with errors"),
    )

    async def broken(texts: Any) -> tuple[tuple[float, ...], ...]:
        raise RuntimeError("vertex is unreachable")

    recalled = asyncio.run(recall.recall(ENTITY, QUERY, client=store, embed=broken))
    assert recalled.entity_ids == (f"belief-{ENTITY}",)
    assert recalled.class_beliefs == ()
    assert recalled.nominated_ids == ()


def test_a_short_vector_batch_is_a_failure_not_a_misalignment() -> None:
    # A response with fewer vectors than statements would otherwise be zipped into a ranking
    # that pairs each statement with the wrong belief's score.
    store = store_with(
        a_class_version("belief-class-a", "statement a"),
        a_class_version("belief-class-b", "statement b"),
    )

    async def short(texts: Any) -> tuple[tuple[float, ...], ...]:
        return (QUERY_VEC, CLOSE)

    with pytest.raises(recall.IndexUnavailable):
        asyncio.run(recall.nominate(QUERY, client=store, embed=short))


def test_an_unreadable_store_raises_rather_than_recalling_nothing() -> None:
    # "The store was unreadable" and "the organization believes nothing" must not look alike.
    store = FakeFirestore({}, error=ServiceUnavailable("firestore is down"))
    with pytest.raises(beliefs.BeliefStoreUnavailable):
        asyncio.run(recall.recall(ENTITY, QUERY, client=store, embed=embedder({})))


def test_a_nomination_the_store_cannot_produce_is_dropped_not_raised() -> None:
    # The index named a belief whose documents are gone: a stale nomination, not a corrupt
    # belief, and the difference is why `resolve()` catches one exception and not the other.
    assert asyncio.run(recall.resolve(["belief-does-not-exist"], client=FakeFirestore({}))) == ()


# --- what an action may rest on -------------------------------------------------------------


def test_a_class_belief_is_never_in_the_ids_an_action_may_cite() -> None:
    # §6.2: advisory only, "may never be the evidence that authorizes an action". `entity_ids`
    # is what `audit.record()` cites, so the cap is a property of the type rather than a rule
    # `incident.py` has to remember.
    store = store_with(
        a_version(1),
        a_class_version("belief-class-config-deploy", "config deploys correlate with errors"),
    )
    embed = embedder({"config deploys correlate with errors": CLOSE})
    recalled = asyncio.run(recall.recall(ENTITY, QUERY, client=store, embed=embed))

    assert recalled.entity_ids == (f"belief-{ENTITY}",)
    assert "belief-class-config-deploy" in recalled.belief_ids
    assert "belief-class-config-deploy" not in recalled.entity_ids
    assert "ADVISORY ONLY" in recalled.summary()


def test_the_query_is_deterministic_and_written_by_no_model() -> None:
    assert QUERY == recall.query_text(
        target=ENTITY,
        signal="error_rate_spike",
        kind="service",
        tier="tier2",
        description="inventory availability and reservation API",
        observed_value=0.38,
    )
    assert ENTITY in QUERY and "error_rate_spike" in QUERY


def test_the_query_names_the_entity_kind_rather_than_assuming_service() -> None:
    """Item 21. The word was the literal "service" until a second domain had suppliers in it."""
    supplier_query = recall.query_text(
        target="SUP-042",
        signal="compliance_lapse",
        kind="supplier",
        tier="tier1",
        description="Verdant Supply Co., a live_goods supplier (contract CTR-2024-0042)",
        observed_value=14.0,
    )
    assert "a tier1 supplier" in supplier_query
    assert "service" not in supplier_query
    # And item 16's measured query shape is unchanged, which is what keeps SIMILARITY_FLOOR
    # a number that was measured against this sentence rather than one like it.
    assert "a tier2 service" in QUERY


# --- the structural guards items 5, 6 and 12 use --------------------------------------------


def test_no_recall_function_returns_an_optional_belief() -> None:
    for name, fn in vars(recall).items():
        if not inspect.isfunction(fn) or fn.__module__ != recall.__name__:
            continue
        returns = get_type_hints(fn).get("return")
        if get_origin(returns) in (Union, types.UnionType):
            args = get_args(returns)
            assert not (beliefs.BeliefVersion in args and type(None) in args), name
            assert not (recall.Recalled in args and type(None) in args), name


def test_the_index_returns_ids_and_nothing_else() -> None:
    # ADR-005's whole division of labour. A `nominate()` that returned versions would be an
    # index that had already read what it is not allowed to see.
    assert get_type_hints(recall.nominate)["return"] == tuple[str, ...]
