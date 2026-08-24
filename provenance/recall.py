"""Recall — the index nominates, the belief store decides (item 16, §6.6).

Two read paths, and the difference between them is the whole design (`docs/adr/ADR-005`):

- **Entity beliefs: exact key, no ML at all.** A deviation on `inventory-api` reads
  `beliefs/belief-inventory-api`, mechanically. Similarity has nothing to contribute to a
  question that is not a similarity question.
- **Class beliefs: Vertex AI embeddings over belief statements**, queried with the incident's
  typed facts — because matching a novel deviation to "deploys altering connection-pool
  parameters correlate with error-rate spikes" genuinely is a similarity problem.

The division of labour is the pre-emptive answer to "isn't this just RAG?", and it is
structural here rather than a promise: `nominate()` reads `beliefs.class_statements()`, which
serves **root documents only** — a root carries `belief_id`, `entity`, `domain`, `scope`,
`statement` and `created_at`, and no status and no confidence. So the index cannot see
currency even by accident. `resolve()` then takes the ids it produced, reads each belief's
current version through the same `beliefs.current()` every other reader uses, and drops
anything `RETRACTED` or `UNKNOWN` (§6.5). A retracted belief that is the closest embedding
match in the world is nominated and then dropped, and both facts reach the trace — which is
why `Recalled` keeps `nominated_ids` beside the survivors. The gap between the two *is* the
guarantee; without it the trace would show only that a retracted belief was absent, which is
also what a broken index looks like.

Three deliberate limits, each with its reason:

- **Nothing stores a vector.** Statements are embedded at query time, in one batched call.
  Class beliefs number in the single digits and will until well past this hackathon, so an
  index endpoint would buy latency nobody is short of at a price that bills whether or not it
  serves a request. A stored vector is also a second thing that can disagree with the
  statement it came from. ponytail: brute-force cosine; the upgrade path is Vertex AI Vector
  Search, and the shape of `nominate()` does not change when it happens.
- **The embedding path fails closed and fails alone.** A Vertex error yields *no* class
  nominations rather than all of them, and the exact-key entity read proceeds regardless. §6.1
  promises a mechanical read; making it depend on a model being reachable would be a strictly
  worse guarantee than the one it replaces.
- **The index nominates ids and nothing else** — `nominate()`'s return type is
  `tuple[str, ...]` and that is not an accident of convenience.

Statements are authored for CLASS beliefs, which item 23 is what produces. Until then every
class belief in the store is hand-seeded by `scripts/verify_recall.py`, which is the posture
items 8, 14 and 15 used to prove a mechanism ahead of its producer.
"""

from __future__ import annotations

import math
import os
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any, Protocol

from provenance import beliefs, models, policy
from provenance.beliefs import BeliefNotFound, BeliefVersion

# How many candidates the index may nominate, and how similar it must find them first. Both
# are fixed, published constants for the same reason §4.2's risk table and §4.3's weights are
# (ADR-002, ADR-003): the defence of a number is that it is inspectable and does not move, not
# that it is optimal. Without the floor, "the top 3 of the 2 beliefs that exist" is everything.
#
# The floor was measured rather than guessed, and the measurement is worth knowing before
# anyone tunes it. `text-embedding-005` scores short business sentences in a compressed band:
# against an `error_rate_spike on inventory-api` query, a genuinely unrelated supply-chain
# statement scored 0.523 while infrastructure statements scored 0.628-0.731. But the *same*
# statements scored 0.696 against a deliberately absurd query about a cafeteria menu. So this
# number discriminates between statements for one query -- which is what nomination is -- and
# emphatically not between a relevant query and an irrelevant one. Do not read a score here as
# a confidence: nothing downstream does, because the store decides and the index only proposes.
NOMINATE_K = 3
SIMILARITY_FLOOR = 0.55

# §3.2's two universal statuses. A belief in either state is never handed to a reasoning
# agent: `RETRACTED` is §6.4's disproven belief, `UNKNOWN` is §6.5's stale one, and the
# Sweeper that writes the second is item 29's. Recall drops both from every path, so item 29
# has to write a status and not also remember to fix a read.
DROPPED_STATUSES = (policy.RETRACTED, policy.UNKNOWN)


class Embedder(Protocol):
    """How `nominate()` turns text into vectors. A parameter so tests need no network."""

    async def __call__(self, texts: Sequence[str]) -> tuple[tuple[float, ...], ...]: ...


class IndexUnavailable(Exception):
    """The embedding index could not be consulted. Caught by `recall()`, never by a caller.

    Distinct from `beliefs.BeliefStoreUnavailable`, which propagates: an unreachable *store*
    means nothing can be said about what is currently believed, while an unreachable *index*
    only means no class belief was nominated. The first must not be silently survivable and
    the second must not take the exact-key read down with it.
    """


@dataclass(frozen=True)
class Recalled:
    """What memory hands one incident: the governed objects, plus what the index proposed.

    `entity` and `class_beliefs` are kept apart rather than concatenated because they are not
    interchangeable downstream. §6.2 caps a class belief as ADVISORY ONLY — it may reorder
    what a domain agent investigates first and may never be the evidence that authorizes an
    action — so the authorization ledger cites `entity_ids` and not `belief_ids`. Merging the
    two would make that cap something `incident.py` has to remember rather than something the
    type makes awkward to get wrong.
    """

    entity: tuple[BeliefVersion, ...] = ()
    class_beliefs: tuple[BeliefVersion, ...] = ()
    nominated_ids: tuple[str, ...] = ()

    @property
    def entity_ids(self) -> tuple[str, ...]:
        """What an action may rest on. This is what the audit ledger (§6.4) cites."""
        return tuple(b.belief_id for b in self.entity)

    @property
    def belief_ids(self) -> tuple[str, ...]:
        """Everything that survived the store's currency filter. The span carries this."""
        return self.entity_ids + tuple(b.belief_id for b in self.class_beliefs)

    def summary(self) -> str:
        """One line per surviving belief, for the prompts that interpolate it.

        Confidence is rendered because §6.6 says recall hands over "the governed object with
        its computed confidence" — a belief with no number attached invites a reader to treat
        it as certain. Class beliefs are labelled advisory in the text a model actually sees,
        which is belt-and-braces beside the structural split above, not a substitute for it.
        """
        lines = [
            f"{b.belief_id} v{b.version}: {b.entity} is {b.status} (confidence {b.confidence:.2f})"
            for b in self.entity
        ]
        lines += [
            f"{b.belief_id} v{b.version} [ADVISORY ONLY, may not justify an action]: "
            f"{b.statement} (confidence {b.confidence:.2f})"
            for b in self.class_beliefs
        ]
        return "; ".join(lines) if lines else "none"


def query_text(
    *, target: str, signal: str, kind: str, tier: str, description: str, observed_value: float
) -> str:
    """§6.6's "queried with the incident's typed facts", as one deterministic string.

    Built from the trigger and the entity model — the same authorities `_seed_state()` uses —
    and never by a model, so the same incident nominates the same candidates every run. Takes
    primitives rather than a `Trigger` because `Trigger` lives in `incident.py` and importing
    it here would close a cycle.

    `kind` was the literal word "service" until item 21, which is the sort of thing that goes
    unnoticed until a second domain arrives: a supplier incident would have queried the index
    with a sentence calling its supplier a service. It comes from `company.described()`, the
    same read the routing kind check makes, so the shape item 16 measured `SIMILARITY_FLOOR`
    against is preserved rather than thinned out.
    """
    return f"{signal} on {target}, a {tier} {kind} ({description}); observed {observed_value}"


async def _vertex_embed(texts: Sequence[str]) -> tuple[tuple[float, ...], ...]:
    """The real embedder: one batched Vertex AI call for the query and every statement."""
    from google import genai

    client = genai.Client(
        vertexai=True,
        project=os.environ.get("GOOGLE_CLOUD_PROJECT"),
        location=models.LOCATION,
    )
    response = await client.aio.models.embed_content(model=models.EMBEDDING, contents=list(texts))
    return tuple(tuple(e.values or ()) for e in (response.embeddings or ()))


def cosine(a: Sequence[float], b: Sequence[float]) -> float:
    """Plain cosine similarity. Returns 0.0 for a zero vector rather than dividing by it."""
    norm = math.sqrt(sum(x * x for x in a)) * math.sqrt(sum(y * y for y in b))
    return sum(x * y for x, y in zip(a, b, strict=True)) / norm if norm else 0.0


async def nominate(
    query: str, *, client: Any | None = None, embed: Embedder | None = None
) -> tuple[str, ...]:
    """The index. Returns belief **ids only**, best match first (§6.6, ADR-005).

    It reads root documents, never versions, so it has no way to know what it is nominating
    is current — that is `resolve()`'s job and the entire point of splitting them.
    """
    statements = await beliefs.class_statements(client=client)
    if not statements:
        return ()

    embedder = embed or _vertex_embed
    try:
        vectors = await embedder([query, *(text for _, text in statements)])
    except Exception as exc:
        # The embedding call can fail on auth, quota, network or a model id; none of them are
        # distinguishable to a caller that is going to do the same thing regardless, which is
        # nominate nothing. Narrowing this would mean importing genai's exception tree into a
        # module that otherwise does not need genai imported at all.
        raise IndexUnavailable(str(exc)) from exc

    if len(vectors) != len(statements) + 1:
        raise IndexUnavailable(f"expected {len(statements) + 1} vectors, got {len(vectors)}")

    scored = sorted(
        (
            (cosine(vectors[0], vector), belief_id)
            for (belief_id, _), vector in zip(statements, vectors[1:], strict=True)
        ),
        reverse=True,
    )
    return tuple(belief_id for score, belief_id in scored if score >= SIMILARITY_FLOOR)[:NOMINATE_K]


async def resolve(ids: Sequence[str], *, client: Any | None = None) -> tuple[BeliefVersion, ...]:
    """The store. Resolves nominated ids to current versions and drops what is not current.

    A `BeliefNotFound` is dropped rather than raised: the index named something the store
    cannot produce, which is a stale nomination and not a corrupt belief. A
    `BeliefStoreUnavailable` propagates untouched — "the store was unreadable" and "there is
    nothing to recall" must not look alike (§7.3), or an outage silently reads as an
    organization that believes nothing.
    """
    found = []
    for belief_id in ids:
        try:
            version = await beliefs.current(belief_id, client=client)
        except BeliefNotFound:
            continue
        if version.status not in DROPPED_STATUSES:
            found.append(version)
    return tuple(found)


async def recall(
    entity_id: str, query: str, *, client: Any | None = None, embed: Embedder | None = None
) -> Recalled:
    """What memory already believes, for one incident (§6.6).

    The two halves are independent by design: an index that cannot be reached costs the class
    nominations and nothing else, because §6.1's exact-key read is mechanical and must not
    acquire a dependency on a model being up.
    """
    entity = await resolve([beliefs.belief_id_for(entity_id)], client=client)
    try:
        nominated = await nominate(query, client=client, embed=embed)
    except IndexUnavailable:
        return Recalled(entity=entity)
    return Recalled(
        entity=entity,
        class_beliefs=await resolve(nominated, client=client),
        nominated_ids=nominated,
    )
