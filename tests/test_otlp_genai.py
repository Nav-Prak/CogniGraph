import json
from pathlib import Path

import pytest

from cognigraph.cli import main
from cognigraph.schemas.enums import RuntimeEdgeType
from cognigraph.trace.adapters.base import TraceLoadError
from cognigraph.trace.adapters.otlp_genai import trace_from_otlp_genai
from cognigraph.trace.loader import available_trace_formats, load_trace

FIXTURES_DIR = Path(__file__).resolve().parent.parent / "fixtures"
SAMPLE = FIXTURES_DIR / "sample_genai_trace.json"


def span(span_id, name, attrs, parent=None, trace_id="t1"):
    out = {
        "traceId": trace_id,
        "spanId": span_id,
        "name": name,
        "startTimeUnixNano": "1718200800000000000",
        "attributes": [
            {"key": k, "value": {"stringValue": v}} for k, v in attrs.items()
        ],
    }
    if parent:
        out["parentSpanId"] = parent
    return out


def wrap(spans):
    return {"resourceSpans": [{"scopeSpans": [{"spans": spans}]}]}


class TestOtlpGenAiAdapter:
    def test_registered(self):
        formats = available_trace_formats()
        assert "otlp-genai" in formats
        assert "genai" in formats

    def test_sample_trace_maps_tool_calls(self):
        trace = load_trace(SAMPLE, trace_format="otlp-genai")
        assert trace.source.type == "otlp-genai"
        assert len(trace.events) == 2
        edges = {(e.source_id, e.target_id) for e in trace.events}
        assert edges == {
            ("host_agent", "filesystem_tool"),
            ("host_agent", "github_tool"),
        }
        assert all(e.edge_type == RuntimeEdgeType.INVOKED for e in trace.events)

    def test_agent_resolved_from_parent_chain(self):
        raw = wrap(
            [
                span("a1", "invoke_agent planner", {
                    "gen_ai.operation.name": "invoke_agent",
                    "gen_ai.agent.name": "planner",
                }),
                span("b1", "subtask", {}, parent="a1"),
                span("c1", "execute_tool shell", {
                    "gen_ai.operation.name": "execute_tool",
                    "gen_ai.tool.name": "shell",
                }, parent="b1"),
            ]
        )
        trace = trace_from_otlp_genai(raw)
        assert trace.events[0].source_id == "planner"
        assert trace.events[0].target_id == "shell"

    def test_agent_id_fallback(self):
        raw = wrap(
            [
                span("c1", "execute_tool shell", {
                    "gen_ai.operation.name": "execute_tool",
                    "gen_ai.tool.name": "shell",
                    "gen_ai.agent.id": "agent-007",
                }),
            ]
        )
        trace = trace_from_otlp_genai(raw)
        assert trace.events[0].source_id == "agent_007"

    def test_tool_name_from_mcp_span_name(self):
        raw = wrap(
            [
                span("c1", "tools/call read_file", {
                    "gen_ai.agent.name": "host",
                }),
            ]
        )
        trace = trace_from_otlp_genai(raw)
        assert trace.events[0].target_id == "read_file"

    def test_spans_without_agent_are_skipped(self):
        raw = wrap(
            [
                span("c1", "execute_tool shell", {
                    "gen_ai.operation.name": "execute_tool",
                    "gen_ai.tool.name": "shell",
                }),
                span("c2", "execute_tool other", {
                    "gen_ai.operation.name": "execute_tool",
                    "gen_ai.tool.name": "other",
                    "gen_ai.agent.name": "host",
                }),
            ]
        )
        trace = trace_from_otlp_genai(raw)
        assert len(trace.events) == 1
        assert trace.events[0].target_id == "other"

    def test_non_tool_spans_ignored(self):
        raw = wrap(
            [
                span("c1", "chat gpt", {
                    "gen_ai.operation.name": "chat",
                    "gen_ai.agent.name": "host",
                }),
            ]
        )
        with pytest.raises(TraceLoadError, match="did not contain any"):
            trace_from_otlp_genai(raw)

    def test_parent_cycle_does_not_hang(self):
        s1 = span("a1", "execute_tool shell", {
            "gen_ai.operation.name": "execute_tool",
            "gen_ai.tool.name": "shell",
        }, parent="a2")
        s2 = span("a2", "wrapper", {}, parent="a1")
        with pytest.raises(TraceLoadError, match="did not contain any"):
            trace_from_otlp_genai(wrap([s1, s2]))

    def test_no_message_content_copied(self):
        raw = wrap(
            [
                span("c1", "execute_tool shell", {
                    "gen_ai.operation.name": "execute_tool",
                    "gen_ai.tool.name": "shell",
                    "gen_ai.agent.name": "host",
                    "gen_ai.input.messages": "SENSITIVE PROMPT CONTENT",
                }),
            ]
        )
        trace = trace_from_otlp_genai(raw)
        dumped = trace.model_dump_json()
        assert "SENSITIVE PROMPT CONTENT" not in dumped

    def test_rejects_non_object(self):
        with pytest.raises(TraceLoadError, match="Expected OTLP JSON object"):
            trace_from_otlp_genai([1, 2])

    def test_load_bad_json_file(self, tmp_path):
        bad = tmp_path / "bad.json"
        bad.write_text("nope")
        with pytest.raises(TraceLoadError, match="Invalid JSON trace file"):
            load_trace(bad, trace_format="otlp-genai")

    def test_load_missing_file(self, tmp_path):
        with pytest.raises(TraceLoadError, match="Could not read trace file"):
            load_trace(tmp_path / "nope.json", trace_format="otlp-genai")


class TestGenAiEndToEnd:
    def test_collected_fixture_with_genai_trace_overlay(self, tmp_path, capsys):
        fixture_path = tmp_path / "fixture.yaml"
        rc = main(
            [
                "collect",
                str(FIXTURES_DIR / "sample_mcp_config.json"),
                "-o",
                str(fixture_path),
            ]
        )
        assert rc == 0
        capsys.readouterr()

        rc = main(
            [
                str(fixture_path),
                "--trace",
                str(SAMPLE),
                "--trace-format",
                "otlp-genai",
            ]
        )
        out = capsys.readouterr().out
        assert rc == 0  # skeleton has no capabilities annotated yet
        assert "Runtime Overlay Summary" in out
        assert "Observed edges: 2" in out
