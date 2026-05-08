import pytest

from cognigraph.fixture.models import FixtureConfig
from cognigraph.graph.builder import CogniGraph, build_from_fixture
from cognigraph.schemas.enums import EdgeType, NodeType


class TestBuildFromFixture:
    def test_node_count(self, sample_graph: CogniGraph):
        # 1 context_source + 1 agent + 2 tools + 2 mcp_servers + 4 capabilities + 2 resources = 12
        assert sample_graph.node_count == 12

    def test_edge_count(self, sample_graph: CogniGraph):
        # CONSUMED_BY: 1 (webpage -> agent)
        # CAN_INVOKE: 2 (agent -> fs_tool, agent -> gh_tool)
        # EXPOSES_CAPABILITY: 4 (fs_tool -> 2 caps, gh_tool -> 2 caps)
        # USES_SERVER: 2 (fs_tool -> fs_mcp, gh_tool -> gh_mcp)
        # CAN_ACCESS_RESOURCE: 2 (SecretRead -> ssh_key, GitHubPush -> repo)
        # Total: 11
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

    def test_reachable_by_invocation(self, sample_graph: CogniGraph):
        tools = sample_graph.get_reachable_by_invocation("planner_agent", 5)
        assert tools == {"filesystem_tool", "github_tool"}

    def test_predecessors(self, sample_graph: CogniGraph):
        preds = sample_graph.get_predecessors("planner_agent", EdgeType.CONSUMED_BY)
        assert preds == ["external_webpage"]
