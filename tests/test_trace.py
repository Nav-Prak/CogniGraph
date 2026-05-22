import json
from pathlib import Path

import pytest

from cognigraph.graph.builder import CogniGraph, build_from_fixture
from cognigraph.schemas.enums import RuntimeEdgeType
from cognigraph.trace.loader import load_trace
from cognigraph.trace.models import TraceEvent, TraceLog
from cognigraph.trace.overlay import (
    OverlayResult,
    apply_overlay,
    get_exercised_static_edges,
    get_runtime_only_edges,
    get_unexercised_static_edges,
)

FIXTURES_DIR = Path(__file__).resolve().parent.parent / "fixtures"


class TestTraceModels:
    def test_trace_event_construction(self):
        event = TraceEvent(
            timestamp="2026-05-01T10:00:00Z",
            source_id="agent_a",
            target_id="tool_b",
            edge_type=RuntimeEdgeType.INVOKED,
        )
        assert event.source_id == "agent_a"
        assert event.edge_type == RuntimeEdgeType.INVOKED
        assert event.metadata == {}

    def test_trace_event_with_metadata(self):
        event = TraceEvent(
            timestamp="2026-05-01T10:00:00Z",
            source_id="a",
            target_id="b",
            edge_type=RuntimeEdgeType.READ_FROM,
            metadata={"path": "/tmp/file"},
        )
        assert event.metadata["path"] == "/tmp/file"

    def test_trace_event_frozen(self):
        event = TraceEvent(
            timestamp="2026-05-01T10:00:00Z",
            source_id="a",
            target_id="b",
            edge_type=RuntimeEdgeType.INVOKED,
        )
        with pytest.raises(Exception):
            event.source_id = "changed"

    def test_trace_event_invalid_edge_type(self):
        with pytest.raises(Exception):
            TraceEvent(
                timestamp="2026-05-01T10:00:00Z",
                source_id="a",
                target_id="b",
                edge_type="INVALID_TYPE",
            )

    def test_trace_log_construction(self):
        events = [
            TraceEvent(
                timestamp="2026-05-01T10:00:00Z",
                source_id="a",
                target_id="b",
                edge_type=RuntimeEdgeType.INVOKED,
            )
        ]
        log = TraceLog(trace_id="trace-001", events=events)
        assert log.trace_id == "trace-001"
        assert len(log.events) == 1

    def test_trace_log_frozen(self):
        log = TraceLog(trace_id="t1", events=[])
        with pytest.raises(Exception):
            log.trace_id = "changed"


class TestTraceLoader:
    def test_load_sample_trace(self):
        trace = load_trace(FIXTURES_DIR / "sample_trace.json")
        assert trace.trace_id == "trace-001"
        assert len(trace.events) == 5

    def test_load_trace_event_types(self):
        trace = load_trace(FIXTURES_DIR / "sample_trace.json")
        edge_types = [e.edge_type for e in trace.events]
        assert RuntimeEdgeType.INVOKED in edge_types
        assert RuntimeEdgeType.READ_FROM in edge_types
        assert RuntimeEdgeType.WROTE_TO in edge_types

    def test_load_trace_bad_file(self, tmp_path):
        bad = tmp_path / "bad.json"
        bad.write_text("not json")
        with pytest.raises(Exception):
            load_trace(bad)

    def test_load_trace_invalid_schema(self, tmp_path):
        bad = tmp_path / "bad.json"
        bad.write_text(json.dumps({"trace_id": "t1", "events": [{"bad": "data"}]}))
        with pytest.raises(Exception):
            load_trace(bad)


class TestOverlayResult:
    def test_empty_result(self):
        result = OverlayResult()
        assert result.observed_count == 0
        assert result.unexpected_count == 0
        assert result.unmatched_nodes == []


class TestOverlay:
    def test_apply_overlay_marks_existing_edges_observed(self, sample_graph):
        trace = TraceLog(
            trace_id="t1",
            events=[
                TraceEvent(
                    timestamp="2026-05-01T10:00:00Z",
                    source_id="planner_agent",
                    target_id="filesystem_tool",
                    edge_type=RuntimeEdgeType.INVOKED,
                ),
            ],
        )
        result = apply_overlay(sample_graph, trace)
        assert result.observed_count == 1
        assert result.unexpected_count == 0
        edge_data = sample_graph._graph["planner_agent"]["filesystem_tool"]
        assert edge_data.get("observed") is True

    def test_apply_overlay_adds_runtime_edges(self, sample_graph):
        trace = TraceLog(
            trace_id="t1",
            events=[
                TraceEvent(
                    timestamp="2026-05-01T10:00:00Z",
                    source_id="planner_agent",
                    target_id="ssh_private_key",
                    edge_type=RuntimeEdgeType.READ_FROM,
                ),
            ],
        )
        result = apply_overlay(sample_graph, trace)
        assert result.unexpected_count == 1
        assert sample_graph._graph.has_edge("planner_agent", "ssh_private_key")
        edge_data = sample_graph._graph["planner_agent"]["ssh_private_key"]
        assert edge_data.get("runtime") is True

    def test_apply_overlay_unmatched_nodes(self, sample_graph):
        trace = TraceLog(
            trace_id="t1",
            events=[
                TraceEvent(
                    timestamp="2026-05-01T10:00:00Z",
                    source_id="nonexistent_agent",
                    target_id="filesystem_tool",
                    edge_type=RuntimeEdgeType.INVOKED,
                ),
            ],
        )
        result = apply_overlay(sample_graph, trace)
        assert "nonexistent_agent" in result.unmatched_nodes
        assert result.observed_count == 0

    def test_apply_overlay_unmatched_target(self, sample_graph):
        trace = TraceLog(
            trace_id="t1",
            events=[
                TraceEvent(
                    timestamp="2026-05-01T10:00:00Z",
                    source_id="planner_agent",
                    target_id="nonexistent_tool",
                    edge_type=RuntimeEdgeType.INVOKED,
                ),
            ],
        )
        result = apply_overlay(sample_graph, trace)
        assert "nonexistent_tool" in result.unmatched_nodes

    def test_full_sample_trace_overlay(self, sample_graph):
        trace = load_trace(FIXTURES_DIR / "sample_trace.json")
        result = apply_overlay(sample_graph, trace)
        assert result.observed_count > 0

    def test_get_exercised_static_edges(self, sample_graph):
        trace = TraceLog(
            trace_id="t1",
            events=[
                TraceEvent(
                    timestamp="2026-05-01T10:00:00Z",
                    source_id="planner_agent",
                    target_id="filesystem_tool",
                    edge_type=RuntimeEdgeType.INVOKED,
                ),
            ],
        )
        apply_overlay(sample_graph, trace)
        exercised = get_exercised_static_edges(sample_graph)
        assert ("planner_agent", "filesystem_tool") in exercised

    def test_get_unexercised_static_edges(self, sample_graph):
        trace = TraceLog(trace_id="t1", events=[])
        apply_overlay(sample_graph, trace)
        unexercised = get_unexercised_static_edges(sample_graph)
        assert len(unexercised) == 11

    def test_get_runtime_only_edges(self, sample_graph):
        trace = TraceLog(
            trace_id="t1",
            events=[
                TraceEvent(
                    timestamp="2026-05-01T10:00:00Z",
                    source_id="planner_agent",
                    target_id="ssh_private_key",
                    edge_type=RuntimeEdgeType.READ_FROM,
                ),
            ],
        )
        apply_overlay(sample_graph, trace)
        runtime_only = get_runtime_only_edges(sample_graph)
        assert ("planner_agent", "ssh_private_key") in runtime_only


class TestCLIWithTrace:
    SAMPLE = str(FIXTURES_DIR / "sample_fixture.yaml")
    TRACE = str(FIXTURES_DIR / "sample_trace.json")

    def test_trace_flag_prints_overlay_summary(self, capsys):
        from cognigraph.cli import main

        main([self.SAMPLE, "--trace", self.TRACE])
        out = capsys.readouterr().out
        assert "Runtime Overlay Summary" in out
        assert "Observed edges:" in out

    def test_trace_flag_quiet(self, capsys):
        from cognigraph.cli import main

        rc = main([self.SAMPLE, "--trace", self.TRACE, "--quiet"])
        out = capsys.readouterr().out
        assert out == ""
        assert rc == 2

    def test_trace_flag_with_dot_export(self, tmp_path):
        from cognigraph.cli import main

        dot_path = tmp_path / "graph.dot"
        main([self.SAMPLE, "--trace", self.TRACE, "--quiet", "--export-dot", str(dot_path)])
        content = dot_path.read_text()
        assert "digraph CogniGraph" in content
        assert "dashed" in content or "runtime" in content.lower() or "observed" in content.lower()

    def test_trace_flag_with_html_report(self, tmp_path):
        from cognigraph.cli import main

        html_path = tmp_path / "report.html"
        main([self.SAMPLE, "--trace", self.TRACE, "--quiet", "--html-report", str(html_path)])
        content = html_path.read_text()
        assert "Runtime Overlay" in content
        assert "runtime-only edges" in content
        assert "Static edge coverage" in content

    def test_bad_trace_returns_1(self, tmp_path, capsys):
        from cognigraph.cli import main

        bad = tmp_path / "bad.json"
        bad.write_text("not json")
        rc = main([self.SAMPLE, "--trace", str(bad), "--quiet"])
        assert rc == 1
