from cognigraph.trace.adapters.base import TraceAdapter, TraceLoadError
from cognigraph.trace.adapters.internal_json import InternalJsonTraceAdapter
from cognigraph.trace.adapters.otlp_json import OtlpJsonTraceAdapter

__all__ = [
    "InternalJsonTraceAdapter",
    "OtlpJsonTraceAdapter",
    "TraceAdapter",
    "TraceLoadError",
]
