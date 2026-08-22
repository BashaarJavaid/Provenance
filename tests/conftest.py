"""One global tracer provider for the whole suite.

OpenTelemetry lets the global provider be set exactly once — a second
`set_tracer_provider()` is ignored with a warning, and the losing module's exporter then
silently receives nothing. Two modules emit spans (item 2's schema contract and item 7's
gateway), so the provider is created here once and each attaches its own in-memory exporter
to it. Each module still clears only its own exporter between tests.
"""

from __future__ import annotations

from opentelemetry import trace
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import SimpleSpanProcessor
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter

from provenance import telemetry

PROVIDER = TracerProvider()
trace.set_tracer_provider(PROVIDER)

# Item 11's span buffer, attached here for the same reason this file exists. `TestClient` is
# used as a context manager, so the app lifespan runs and `configure_tracing()` builds its
# own provider -- whose `set_tracer_provider()` call loses to the one above. The buffer would
# then hang off a provider nothing traces through, and /trace would be empty under test.
PROVIDER.add_span_processor(telemetry.BUFFER)


def attach_exporter() -> InMemorySpanExporter:
    """An in-memory exporter fed by the one global provider."""
    exporter = InMemorySpanExporter()
    PROVIDER.add_span_processor(SimpleSpanProcessor(exporter))
    return exporter
