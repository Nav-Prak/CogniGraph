from __future__ import annotations

from pathlib import Path

from cognigraph.trace.adapters.base import TraceAdapter, TraceLoadError
from cognigraph.trace.adapters.internal_json import InternalJsonTraceAdapter
from cognigraph.trace.adapters.otlp_genai import OtlpGenAiTraceAdapter
from cognigraph.trace.adapters.otlp_json import OtlpJsonTraceAdapter
from cognigraph.trace.models import TraceLog

_ADAPTERS: dict[str, TraceAdapter] = {}


def register_trace_adapter(
    adapter: TraceAdapter,
    *,
    aliases: tuple[str, ...] = (),
) -> None:
    for name in (adapter.format_name, *aliases):
        _ADAPTERS[name] = adapter


def available_trace_formats() -> tuple[str, ...]:
    return tuple(sorted(_ADAPTERS))


def get_trace_adapter(trace_format: str) -> TraceAdapter:
    try:
        return _ADAPTERS[trace_format]
    except KeyError as e:
        supported = ", ".join(available_trace_formats())
        raise TraceLoadError(
            f"Unsupported trace format '{trace_format}'. Supported formats: {supported}"
        ) from e


def load_trace(path: Path, trace_format: str = "internal-json") -> TraceLog:
    return get_trace_adapter(trace_format).load(Path(path))


register_trace_adapter(
    InternalJsonTraceAdapter(),
    aliases=("internal", "cognigraph-trace-v1", "json"),
)
register_trace_adapter(OtlpJsonTraceAdapter())
register_trace_adapter(OtlpGenAiTraceAdapter(), aliases=("genai",))
