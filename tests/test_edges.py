import pytest
from pydantic import ValidationError

from cognigraph.schemas.edges import (
    ALLOWED_RELATIONSHIPS,
    INVALID_RELATIONSHIPS,
    Edge,
    is_invalid_relationship,
    validate_edge_types,
)
from cognigraph.schemas.enums import EdgeType, NodeType


class TestAllowedRelationships:
    def test_has_nine_entries(self):
        assert len(ALLOWED_RELATIONSHIPS) == 9

    def test_policy_applies_to_targets(self):
        targets = ALLOWED_RELATIONSHIPS[(NodeType.POLICY, EdgeType.APPLIES_TO)]
        assert targets == {NodeType.AGENT, NodeType.TOOL, NodeType.MCP_SERVER}

    def test_policy_cannot_apply_to_capability(self):
        assert not validate_edge_types(
            NodeType.POLICY, EdgeType.APPLIES_TO, NodeType.CAPABILITY
        )

    def test_context_source_consumed_by_agent(self):
        assert validate_edge_types(
            NodeType.CONTEXT_SOURCE, EdgeType.CONSUMED_BY, NodeType.AGENT
        )

    def test_agent_can_invoke_tool(self):
        assert validate_edge_types(
            NodeType.AGENT, EdgeType.CAN_INVOKE, NodeType.TOOL
        )

    def test_tool_can_invoke_tool(self):
        assert validate_edge_types(
            NodeType.TOOL, EdgeType.CAN_INVOKE, NodeType.TOOL
        )

    def test_tool_exposes_capability(self):
        assert validate_edge_types(
            NodeType.TOOL, EdgeType.EXPOSES_CAPABILITY, NodeType.CAPABILITY
        )

    def test_capability_can_access_resource(self):
        assert validate_edge_types(
            NodeType.CAPABILITY, EdgeType.CAN_ACCESS_RESOURCE, NodeType.RESOURCE
        )

    def test_tool_uses_server(self):
        assert validate_edge_types(
            NodeType.TOOL, EdgeType.USES_SERVER, NodeType.MCP_SERVER
        )

    def test_agent_runs_in_environment(self):
        assert validate_edge_types(
            NodeType.AGENT, EdgeType.RUNS_IN, NodeType.EXECUTION_ENVIRONMENT
        )

    def test_tool_runs_in_environment(self):
        assert validate_edge_types(
            NodeType.TOOL, EdgeType.RUNS_IN, NodeType.EXECUTION_ENVIRONMENT
        )

    def test_reject_unknown_combination(self):
        assert not validate_edge_types(
            NodeType.AGENT, EdgeType.CONSUMED_BY, NodeType.TOOL
        )


class TestInvalidRelationships:
    def test_has_eight_entries(self):
        assert len(INVALID_RELATIONSHIPS) == 8

    @pytest.mark.parametrize(
        "source,target",
        [
            (NodeType.CONTEXT_SOURCE, NodeType.CAPABILITY),
            (NodeType.CONTEXT_SOURCE, NodeType.RESOURCE),
            (NodeType.AGENT, NodeType.RESOURCE),
            (NodeType.AGENT, NodeType.CAPABILITY),
            (NodeType.MCP_SERVER, NodeType.CAPABILITY),
            (NodeType.RESOURCE, NodeType.TOOL),
            (NodeType.CAPABILITY, NodeType.AGENT),
            (NodeType.RESOURCE, NodeType.CONTEXT_SOURCE),
        ],
    )
    def test_invalid_pair(self, source, target):
        assert is_invalid_relationship(source, target)

    def test_valid_pair_not_flagged(self):
        assert not is_invalid_relationship(NodeType.AGENT, NodeType.TOOL)


class TestEdgeModel:
    def test_valid_edge(self):
        edge = Edge(
            source_id="webpage",
            target_id="planner",
            edge_type=EdgeType.CONSUMED_BY,
            source_node_type=NodeType.CONTEXT_SOURCE,
            target_node_type=NodeType.AGENT,
        )
        assert edge.source_id == "webpage"
        assert edge.target_id == "planner"

    def test_invalid_edge_raises(self):
        with pytest.raises(ValidationError, match="Invalid edge"):
            Edge(
                source_id="ctx",
                target_id="cap",
                edge_type=EdgeType.CONSUMED_BY,
                source_node_type=NodeType.CONTEXT_SOURCE,
                target_node_type=NodeType.CAPABILITY,
            )

    def test_agent_cannot_expose_capability(self):
        with pytest.raises(ValidationError, match="Invalid edge"):
            Edge(
                source_id="agent",
                target_id="cap",
                edge_type=EdgeType.EXPOSES_CAPABILITY,
                source_node_type=NodeType.AGENT,
                target_node_type=NodeType.CAPABILITY,
            )

    def test_resource_cannot_invoke_tool(self):
        with pytest.raises(ValidationError, match="Invalid edge"):
            Edge(
                source_id="res",
                target_id="tool",
                edge_type=EdgeType.CAN_INVOKE,
                source_node_type=NodeType.RESOURCE,
                target_node_type=NodeType.TOOL,
            )

    def test_frozen(self):
        edge = Edge(
            source_id="webpage",
            target_id="planner",
            edge_type=EdgeType.CONSUMED_BY,
            source_node_type=NodeType.CONTEXT_SOURCE,
            target_node_type=NodeType.AGENT,
        )
        with pytest.raises(ValidationError):
            edge.source_id = "other"

    def test_all_valid_relationships_create_edges(self):
        for (src_type, edge_type), target_types in ALLOWED_RELATIONSHIPS.items():
            for tgt_type in target_types:
                edge = Edge(
                    source_id="src",
                    target_id="tgt",
                    edge_type=edge_type,
                    source_node_type=src_type,
                    target_node_type=tgt_type,
                )
                assert edge.edge_type == edge_type
