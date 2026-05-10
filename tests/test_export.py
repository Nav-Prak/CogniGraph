import json

from cognigraph.export import _dot_escape, _dot_id, to_dot, to_json
from cognigraph.graph.builder import CogniGraph
from cognigraph.schemas.enums import NodeType


class TestDotEscaping:
    def test_escapes_quotes(self):
        assert _dot_escape('a"b') == 'a\\"b'

    def test_escapes_backslash(self):
        assert _dot_escape("a\\b") == "a\\\\b"

    def test_unique_ids_for_similar_names(self):
        id1 = _dot_id("a-b", NodeType.TOOL)
        id2 = _dot_id("a_b", NodeType.TOOL)
        assert id1 != id2

    def test_unique_ids_across_types(self):
        id1 = _dot_id("shared", NodeType.AGENT)
        id2 = _dot_id("shared", NodeType.TOOL)
        assert id1 != id2


class TestToDot:
    def test_contains_digraph(self, sample_graph: CogniGraph):
        dot = to_dot(sample_graph)
        assert dot.startswith("digraph CogniGraph {")
        assert dot.endswith("}")

    def test_contains_all_nodes(self, sample_graph: CogniGraph):
        dot = to_dot(sample_graph)
        assert "external_webpage" in dot
        assert "planner_agent" in dot
        assert "filesystem_tool" in dot
        assert "SecretRead" in dot
        assert "ssh_private_key" in dot

    def test_contains_edges(self, sample_graph: CogniGraph):
        dot = to_dot(sample_graph)
        assert "CONSUMED_BY" in dot
        assert "CAN_INVOKE" in dot
        assert "EXPOSES_CAPABILITY" in dot

    def test_highlight_paths(self, sample_graph: CogniGraph):
        dot = to_dot(sample_graph, highlight_paths=[
            ["external_webpage", "planner_agent", "filesystem_tool", "SecretRead"]
        ])
        assert 'color="red"' in dot
        assert "penwidth=2.0" in dot

    def test_no_highlight_by_default(self, sample_graph: CogniGraph):
        dot = to_dot(sample_graph)
        assert 'color="red"' not in dot


class TestToJson:
    def test_has_nodes_and_edges(self, sample_graph: CogniGraph):
        data = to_json(sample_graph)
        assert "nodes" in data
        assert "edges" in data

    def test_node_count(self, sample_graph: CogniGraph):
        data = to_json(sample_graph)
        assert len(data["nodes"]) == 12

    def test_edge_count(self, sample_graph: CogniGraph):
        data = to_json(sample_graph)
        assert len(data["edges"]) == 11

    def test_node_has_id_and_type(self, sample_graph: CogniGraph):
        data = to_json(sample_graph)
        for node in data["nodes"]:
            assert "id" in node
            assert "node_type" in node

    def test_edge_has_source_target_type(self, sample_graph: CogniGraph):
        data = to_json(sample_graph)
        for edge in data["edges"]:
            assert "source" in edge
            assert "target" in edge
            assert "edge_type" in edge

    def test_serializable(self, sample_graph: CogniGraph):
        data = to_json(sample_graph)
        serialized = json.dumps(data)
        assert isinstance(serialized, str)
