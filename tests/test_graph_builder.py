import pytest

from cognigraph.fixture.models import FixtureConfig
from cognigraph.graph.builder import CogniGraph, InvalidEdgeError, build_from_fixture
from cognigraph.schemas.enums import EdgeType, NodeType


class TestBuildFromFixture:
    def test_node_count(self, sample_graph: CogniGraph):
        assert sample_graph.node_count == 12

    def test_edge_count(self, sample_graph: CogniGraph):
        assert sample_graph.edge_count == 11

    def test_context_source_nodes(self, sample_graph: CogniGraph):
        cs_nodes = sample_graph.get_nodes_by_type(NodeType.CONTEXT_SOURCE)
        assert cs_nodes == ["external_webpage"]

    def test_agent_nodes(self, sample_graph: CogniGraph):
        agents = sample_graph.get_nodes_by_type(NodeType.AGENT)
        assert agents == ["planner_agent"]

    def test_tool_nodes(self, sample_graph: CogniGraph):
        tools = sample_graph.get_nodes_by_type(NodeType.TOOL)
        assert set(tools) == {"filesystem_tool", "github_tool"}

    def test_capability_nodes(self, sample_graph: CogniGraph):
        caps = sample_graph.get_nodes_by_type(NodeType.CAPABILITY)
        assert set(caps) == {
            "SecretRead", "FilesystemRead", "GitHubPush", "ExternalNetworkSend"
        }

    def test_resource_nodes(self, sample_graph: CogniGraph):
        resources = sample_graph.get_nodes_by_type(NodeType.RESOURCE)
        assert set(resources) == {"ssh_private_key", "github_repository"}

    def test_agent_trust_level(self, sample_graph: CogniGraph):
        agent = sample_graph.get_node("planner_agent")
        assert agent["trust_level"] == 2

    def test_capability_severity(self, sample_graph: CogniGraph):
        cap = sample_graph.get_node("SecretRead")
        assert cap["severity"] == 4

    def test_resource_sensitivity(self, sample_graph: CogniGraph):
        res = sample_graph.get_node("ssh_private_key")
        assert res["sensitivity"] == 4


class TestEdgeValidation:
    def test_rejects_invalid_edge(self):
        graph = CogniGraph()
        graph.add_node("cs", NodeType.CONTEXT_SOURCE, trust_level=0, source_type="webpage")
        graph.add_node("cap", NodeType.CAPABILITY, severity=3)
        with pytest.raises(InvalidEdgeError, match="Invalid edge"):
            graph.add_edge("cs", "cap", EdgeType.CONSUMED_BY)

    @pytest.mark.parametrize(
        "source_type,edge_type,target_type",
        [
            (NodeType.CONTEXT_SOURCE, EdgeType.CONSUMED_BY, NodeType.CAPABILITY),
            (NodeType.CONTEXT_SOURCE, EdgeType.CONSUMED_BY, NodeType.RESOURCE),
            (NodeType.AGENT, EdgeType.CAN_INVOKE, NodeType.RESOURCE),
            (NodeType.AGENT, EdgeType.EXPOSES_CAPABILITY, NodeType.CAPABILITY),
            (NodeType.MCP_SERVER, EdgeType.EXPOSES_CAPABILITY, NodeType.CAPABILITY),
            (NodeType.RESOURCE, EdgeType.CAN_INVOKE, NodeType.TOOL),
            (NodeType.CAPABILITY, EdgeType.CAN_ACCESS_RESOURCE, NodeType.AGENT),
            (NodeType.RESOURCE, EdgeType.CONSUMED_BY, NodeType.CONTEXT_SOURCE),
        ],
    )
    def test_rejects_invalid_relationship_matrix_edges(self, source_type, edge_type, target_type):
        graph = CogniGraph()
        graph.add_node("src", source_type)
        graph.add_node("tgt", target_type)
        with pytest.raises(InvalidEdgeError, match="Invalid edge"):
            graph.add_edge("src", "tgt", edge_type)

    def test_rejects_missing_source(self):
        graph = CogniGraph()
        graph.add_node("tgt", NodeType.TOOL)
        with pytest.raises(InvalidEdgeError, match="does not exist"):
            graph.add_edge("missing", "tgt", EdgeType.CAN_INVOKE)

    def test_rejects_missing_target(self):
        graph = CogniGraph()
        graph.add_node("src", NodeType.AGENT, trust_level=2)
        with pytest.raises(InvalidEdgeError, match="does not exist"):
            graph.add_edge("src", "missing", EdgeType.CAN_INVOKE)

    def test_accepts_valid_edge(self):
        graph = CogniGraph()
        graph.add_node("a", NodeType.AGENT, trust_level=2)
        graph.add_node("t", NodeType.TOOL)
        graph.add_edge("a", "t", EdgeType.CAN_INVOKE)
        assert graph.edge_count == 1


class TestCogniGraphQueries:
    def test_consumed_by_edges(self, sample_graph: CogniGraph):
        agents = sample_graph.get_successors("external_webpage", EdgeType.CONSUMED_BY)
        assert agents == ["planner_agent"]

    def test_can_invoke_edges(self, sample_graph: CogniGraph):
        tools = sample_graph.get_successors("planner_agent", EdgeType.CAN_INVOKE)
        assert set(tools) == {"filesystem_tool", "github_tool"}

    def test_exposes_capability_edges(self, sample_graph: CogniGraph):
        caps = sample_graph.get_capabilities_of_tool("filesystem_tool")
        assert set(caps) == {"SecretRead", "FilesystemRead"}

    def test_can_access_resource_edges(self, sample_graph: CogniGraph):
        resources = sample_graph.get_resources_of_capability("SecretRead")
        assert resources == ["ssh_private_key"]

    def test_uses_server_edges(self, sample_graph: CogniGraph):
        servers = sample_graph.get_successors("filesystem_tool", EdgeType.USES_SERVER)
        assert servers == ["filesystem_mcp"]

    def test_reachable_with_paths(self, sample_graph: CogniGraph):
        paths = sample_graph.get_reachable_with_paths("planner_agent", 5)
        assert set(paths.keys()) == {"filesystem_tool", "github_tool"}
        assert paths["filesystem_tool"] == ["planner_agent", "filesystem_tool"]

    def test_predecessors(self, sample_graph: CogniGraph):
        preds = sample_graph.get_predecessors("planner_agent", EdgeType.CONSUMED_BY)
        assert preds == ["external_webpage"]

    def test_agents_reaching_tool(self, sample_graph: CogniGraph):
        agents = sample_graph.get_agents_reaching_tool("filesystem_tool", 5)
        assert agents == {"planner_agent"}
