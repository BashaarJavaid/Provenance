"""Model Armor screening on untrusted content (§5.1) — the first filter, never the boundary.

Google's managed inline guardrail: one template, prompt-injection/jailbreak detection at
`HIGH` confidence plus Sensitive Data Protection basic screening, and every verdict written
to Cloud Logging **by Model Armor itself** (`log_sanitize_operations` on the template) rather
than restated by us. `scripts/setup_model_armor.py` creates it; `scripts/verify_model_armor.py`
is the live proof.

Three things about this module are worth knowing before changing it.

**Item 26 gave `screen()` its caller** — the paragraph that stood here said nothing did, which
was the honest state while `incident.Trigger` carried no untrusted free text. It now carries
`raw_content`, and `incident.run_incident()` screens it before the incident span opens and
raises `ContentBlocked` on a match: ingest halting means no incident exists, which is §7.3's
row read literally. `docs/adr/ADR-027` records why the wiring waited; `ADR-028` records the
sanitizer that arrived with it.

**It fails closed (§7.3, "Model Armor or sanitizer unavailable → ingest halts").** Any API
failure raises `ScreeningUnavailable`; nothing returns a permissive verdict, and "the filter
matched" never looks like "the service was unreachable". `screen()` does not return
`Verdict | None` for the same reason `registry.get_agent()` does not return `Agent | None`.

**A `Verdict` carries filter names, never payload text.** §8.1 keeps content out of the trace;
this is the one object in the repo that has held raw untrusted content, so it holds the same
line. Item 26's `verify:` clause — raw inbound text never reaches a frontier-model prompt —
gets its first guard here.

Emits **no span**. Item 25 says verdicts are logged, never that they are traced, and §5.1 is
explicit that Model Armor is a filter and not one of the architecture's decisions — so it does
not get a decision span. Five span shapes still, and §8.1 is untouched.
"""

from __future__ import annotations

import asyncio
import os
from dataclasses import dataclass
from typing import Protocol

from google.api_core import exceptions as gexc
from google.api_core.client_options import ClientOptions
from google.cloud import modelarmor_v1

# The template `scripts/setup_model_armor.py` creates. Model Armor has **no global endpoint**:
# a regional template addressed on the default endpoint answers 404, so the endpoint is not a
# tuning knob. `us-central1` is where Firestore, Cloud Run and everything else in this project
# already live, which keeps it at one region to reason about.
LOCATION = "us-central1"
TEMPLATE_ID = "provenance-ingest"
API_ENDPOINT = f"modelarmor.{LOCATION}.rep.googleapis.com"

_MATCH = modelarmor_v1.FilterMatchState.MATCH_FOUND


class Screener(Protocol):
    """The one Model Armor call this module makes. A parameter so tests need no network."""

    def sanitize_user_prompt(
        self, *, request: modelarmor_v1.SanitizeUserPromptRequest
    ) -> modelarmor_v1.SanitizeUserPromptResponse: ...


class ScreeningUnavailable(Exception):
    """Model Armor could not be reached, or answered something we cannot read.

    Distinct from a verdict of "blocked", deliberately. §7.3 puts ingest on the fail-closed
    side: a caller that cannot tell an outage from a clean pass would let untrusted content
    through precisely when the filter is down.
    """


class ContentBlocked(Exception):
    """Model Armor matched, so this content does not travel any further (§7.3).

    Item 26 gave `screen()` its first caller and this its first raiser. Distinct from
    `ScreeningUnavailable` above in exactly the way that one is distinct from a clean pass:
    the filter working and the filter being unreachable are different facts, and a caller that
    could not tell them apart would report an outage as a defence.

    Carries the filter names off the `Verdict`, never the text — the same line the `Verdict`
    itself holds.
    """

    def __init__(self, filters_matched: tuple[str, ...]) -> None:
        super().__init__(f"Model Armor matched {list(filters_matched)}; ingest halts")
        self.filters_matched = filters_matched


@dataclass(frozen=True)
class Verdict:
    """One screening result. Identifiers and enums only — never the text that was screened."""

    blocked: bool
    filters_matched: tuple[str, ...]
    template: str


def template_path(project_id: str) -> str:
    return f"projects/{project_id}/locations/{LOCATION}/templates/{TEMPLATE_ID}"


def _matched(result: modelarmor_v1.FilterResult) -> bool:
    """Whether this one filter fired. SDP nests its match one level deeper than the rest."""
    which = modelarmor_v1.FilterResult.pb(result).WhichOneof("filter_result")
    if which is None:
        return False
    sub = getattr(result, which)
    if which == "sdp_filter_result":
        return any(
            getattr(sub, mode).match_state == _MATCH
            for mode in ("inspect_result", "deidentify_result")
        )
    return bool(sub.match_state == _MATCH)


def _default_client() -> modelarmor_v1.ModelArmorClient:
    return modelarmor_v1.ModelArmorClient(
        transport="rest", client_options=ClientOptions(api_endpoint=API_ENDPOINT)
    )


async def screen(
    text: str, *, project_id: str | None = None, client: Screener | None = None
) -> Verdict:
    """Screen one piece of untrusted content. Raises rather than guessing (§7.3).

    `client` is the injection seam the offline tests use, the same arrangement
    `recall.recall(..., embed=)` and `incident.run_incident(..., model_*=)` already have.
    The Model Armor client is synchronous and this does a network call, so it runs on a
    thread rather than becoming the repo's second sync exception — `action.validate()` is
    the only one, and it earns it by doing no I/O at all.
    """
    project_id = project_id or os.environ.get("GOOGLE_CLOUD_PROJECT")
    if not project_id:
        raise ScreeningUnavailable("GOOGLE_CLOUD_PROJECT is not set")
    name = template_path(project_id)
    api = client if client is not None else _default_client()
    request = modelarmor_v1.SanitizeUserPromptRequest(
        name=name, user_prompt_data=modelarmor_v1.DataItem(text=text)
    )
    try:
        response = await asyncio.to_thread(api.sanitize_user_prompt, request=request)
    except gexc.GoogleAPIError as exc:
        raise ScreeningUnavailable(f"Model Armor call failed: {exc}") from exc

    result = response.sanitization_result
    if result.invocation_result == modelarmor_v1.InvocationResult.FAILURE:
        raise ScreeningUnavailable("Model Armor reported invocation_result=FAILURE")
    return Verdict(
        blocked=result.filter_match_state == _MATCH,
        filters_matched=tuple(sorted(k for k, v in result.filter_results.items() if _matched(v))),
        template=name,
    )
