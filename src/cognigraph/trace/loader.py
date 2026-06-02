from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from cognigraph.schemas.enums import RuntimeEdgeType
from cognigraph.trace.models import TraceLog


class TraceLoadError(Exception):
    pass


def load_trace(path: Path, trace_format: str = "internal") -> TraceLog:
    with open(path, encoding="utf-8") as f:
        raw = json.load(f)
    if trace_format == "internal":
        return TraceLog(**raw)
    if trace_format == "otlp-json":
        return trace_from_otlp_json(raw, fallback_trace_id=path.stem)
    raise TraceLoadError(f"Unsupported trace format '{trace_format}'")


def _otlp_attr_value(value: dict[str, Any]) -> str:
    for key in [
        "stringValue",
        "intValue",
        "doubleValue",
        "boolValue",
        "bytesValue",
    ]:
        if key in value:
            return str(value[key])
    if "arrayValue" in value:
        values = value["arrayValue"].get("values", [])
        return ",".join(_otlp_attr_value(item) for item in values)
    if "kvlistValue" in value:
        values = value["kvlistValue"].get("values", [])
        return ",".join(
            f"{item.get('key', '')}={_otlp_attr_value(item.get('value', {}))}"
            for item in values
        )
    return ""


def _otlp_attributes(span: dict[str, Any]) -> dict[str, str]:
    attrs: dict[str, str] = {}
    for attr in span.get("attributes", []):
        key = attr.get("key")
        value = attr.get("value", {})
        if key:
            attrs[str(key)] = _otlp_attr_value(value)
    return attrs


def _otlp_spans(raw: dict[str, Any]) -> list[dict[str, Any]]:
    spans: list[dict[str, Any]] = []
    for resource_span in raw.get("resourceSpans", []):
        span_groups = [
            *resource_span.get("scopeSpans", []),
            *resource_span.get("instrumentationLibrarySpans", []),
        ]
        for span_group in span_groups:
            spans.extend(span_group.get("spans", []))
    return spans


def _span_timestamp(span: dict[str, Any]) -> str:
    return str(
        span.get("startTimeUnixNano")
        or span.get("start_time_unix_nano")
        or span.get("name")
        or "unknown"
    )


def trace_from_otlp_json(raw: dict[str, Any], fallback_trace_id: str = "otlp-trace") -> TraceLog:
    if not isinstance(raw, dict):
        raise TraceLoadError("Expected OTLP JSON object")

    events = []
    trace_ids: list[str] = []
    for span in _otlp_spans(raw):
        attrs = _otlp_attributes(span)
        source_id = attrs.get("cognigraph.source_id")
        target_id = attrs.get("cognigraph.target_id")
        edge_type = attrs.get("cognigraph.edge_type")
        if not source_id or not target_id or not edge_type:
            continue
        if span.get("traceId"):
            trace_ids.append(str(span["traceId"]))
        metadata = {
            key: value
            for key, value in attrs.items()
            if not key.startswith("cognigraph.")
        }
        events.append(
            {
                "timestamp": _span_timestamp(span),
                "source_id": source_id,
                "target_id": target_id,
                "edge_type": RuntimeEdgeType(edge_type),
                "metadata": metadata,
            }
        )

    if not events:
        raise TraceLoadError(
            "OTLP trace did not contain any spans with cognigraph.source_id, "
            "cognigraph.target_id, and cognigraph.edge_type attributes"
        )

    trace_id = trace_ids[0] if trace_ids else fallback_trace_id
    return TraceLog(trace_id=trace_id, events=events)
