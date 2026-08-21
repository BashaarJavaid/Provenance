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

PROVIDER = TracerProvider()
trace.set_tracer_provider(PROVIDER)


def attach_exporter() -> InMemorySpanExporter:
    """An in-memory exporter fed by the one global provider."""
    exporter = InMemorySpanExporter()
    PROVIDER.add_span_processor(SimpleSpanProcessor(exporter))
    return exporter
