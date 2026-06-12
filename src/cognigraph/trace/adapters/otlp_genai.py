from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from pydantic import ValidationError

from cognigraph.trace.adapters.base import TraceLoadError
from cognigraph.trace.adapters.otlp_json import (
    _otlp_attributes,
    _otlp_spans,
    _span_origin,
    _span_timestamp,
)
from cognigraph.trace.models import TraceLog, TraceSource

# Pinned attribute names from the OTel semantic conventions (both families
# are still in Development status; bump deliberately, never silently):
# - GenAI agent spans: gen_ai.operation.name = execute_tool / invoke_agent,
#   gen_ai.tool.name, gen_ai.agent.name / gen_ai.agent.id
# - MCP spans (semconv v1.39): mcp.method.name = tools/call, mcp.tool.name,
#   span name "tools/call <tool>"
_EXECUTE_TOOL = "execute_tool"
_INVOKE_AGENT = "invoke_agent"
_MCP_TOOLS_CALL = "tools/call"


def _normalize_id(name: str) -> str:
    # Same normalization the collector applies to server/tool names, so
    # spans from collected topologies resolve to fixture node ids.
    normalized = re.sub(r"[^A-Za-z0-9_]", "_", name).strip("_")
    return normalized or "unknown"


def _agent_of_span(span: dict[str, Any]) -> str | None:
    attrs = _otlp_attributes(span)
    return attrs.get("gen_ai.agent.name") or attrs.get("gen_ai.agent.id") or None


def _resolve_agent(
    span: dict[str, Any], spans_by_id: dict[str, dict[str, Any]]
) -> str | None:
    """Find the owning agent: on the span itself, else up the parent chain."""
    seen: set[str] = set()
    current: dict[str, Any] | None = span
    while current is not None:
        agent = _agent_of_span(current)
        if agent:
            return agent
        parent_id = str(current.get("parentSpanId") or "")
        if not parent_id or parent_id in seen:
            return None
        seen.add(parent_id)
        current = spans_by_id.get(parent_id)
    return None


def _tool_of_span(span: dict[str, Any], attrs: dict[str, str]) -> str | None:
    tool = attrs.get("gen_ai.tool.name") or attrs.get("mcp.tool.name")
    if tool:
        return tool
    # MCP semconv span name: "tools/call <tool>"
    name = str(span.get("name") or "")
    if name.startswith(f"{_MCP_TOOLS_CALL} "):
        return name[len(_MCP_TOOLS_CALL) + 1 :].strip() or None
    return None


def _is_tool_call(span: dict[str, Any], attrs: dict[str, str]) -> bool:
    if attrs.get("gen_ai.operation.name") == _EXECUTE_TOOL:
        return True
    if attrs.get("mcp.method.name") == _MCP_TOOLS_CALL:
        return True
    return str(span.get("name") or "").startswith(_MCP_TOOLS_CALL)


def trace_from_otlp_genai(
    raw: dict[str, Any], fallback_trace_id: str = "otlp-genai-trace"
) -> TraceLog:
    """Map standard OTel GenAI / MCP spans to runtime INVOKED events.

    No CogniGraph-specific attributes required: tool calls are detected via
    gen_ai.operation.name=execute_tool or mcp.method.name=tools/call, and the
    invoking agent comes from gen_ai.agent.name on the span or its nearest
    ancestor (invoke_agent spans carry it for their children). Span content
    (messages, arguments) is deliberately NOT copied into events.
    """
    if not isinstance(raw, dict):
        raise TraceLoadError("Expected OTLP JSON object")

    spans = _otlp_spans(raw)
    spans_by_id = {
        str(span["spanId"]): span for span in spans if span.get("spanId")
    }

    events = []
    trace_ids: list[str] = []
    for span in spans:
        attrs = _otlp_attributes(span)
        if not _is_tool_call(span, attrs):
            continue
        tool = _tool_of_span(span, attrs)
        agent = _resolve_agent(span, spans_by_id)
        if not tool or not agent:
            continue
        if span.get("traceId"):
            trace_ids.append(str(span["traceId"]))
        events.append(
            {
                "timestamp": _span_timestamp(span),
                "source_id": _normalize_id(agent),
                "target_id": _normalize_id(tool),
                "edge_type": "INVOKED",
                "origin": _span_origin(span),
                "evidence": {
                    "span_name": str(span.get("name") or ""),
                    "operation": attrs.get("gen_ai.operation.name")
                    or attrs.get("mcp.method.name")
                    or "",
                },
            }
        )

    if not events:
        raise TraceLoadError(
            "OTLP trace did not contain any GenAI/MCP tool-call spans "
            "(gen_ai.operation.name=execute_tool or mcp.method.name=tools/call) "
            "with a resolvable agent and tool name"
        )

    trace_id = trace_ids[0] if trace_ids else fallback_trace_id
    try:
        return TraceLog(
            trace_id=trace_id,
            source=TraceSource(type="otlp-genai"),
            events=events,
        )
    except ValidationError as e:
        raise TraceLoadError(f"Invalid GenAI-derived trace: {e}") from e


class OtlpGenAiTraceAdapter:
    format_name = "otlp-genai"

    def load(self, path: Path) -> TraceLog:
        try:
            with open(path, encoding="utf-8") as f:
                raw = json.load(f)
        except OSError as e:
            raise TraceLoadError(f"Could not read trace file: {e}") from e
        except json.JSONDecodeError as e:
            raise TraceLoadError(f"Invalid JSON trace file: {e}") from e
        return trace_from_otlp_genai(raw, fallback_trace_id=path.stem)
