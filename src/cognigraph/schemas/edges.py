from pydantic import BaseModel, model_validator

from cognigraph.schemas.enums import EdgeType, NodeType

ALLOWED_RELATIONSHIPS: dict[tuple[NodeType, EdgeType], set[NodeType]] = {
    (NodeType.CONTEXT_SOURCE, EdgeType.CONSUMED_BY): {NodeType.AGENT},
    (NodeType.AGENT, EdgeType.CAN_INVOKE): {NodeType.TOOL},
    (NodeType.TOOL, EdgeType.CAN_INVOKE): {NodeType.TOOL},
    (NodeType.TOOL, EdgeType.EXPOSES_CAPABILITY): {NodeType.CAPABILITY},
    (NodeType.CAPABILITY, EdgeType.CAN_ACCESS_RESOURCE): {NodeType.RESOURCE},
    (NodeType.TOOL, EdgeType.USES_SERVER): {NodeType.MCP_SERVER},
    (NodeType.AGENT, EdgeType.RUNS_IN): {NodeType.EXECUTION_ENVIRONMENT},
    (NodeType.TOOL, EdgeType.RUNS_IN): {NodeType.EXECUTION_ENVIRONMENT},
    (NodeType.POLICY, EdgeType.APPLIES_TO): {
        NodeType.AGENT,
        NodeType.TOOL,
        NodeType.MCP_SERVER,
    },
}

INVALID_RELATIONSHIPS: set[tuple[NodeType, NodeType]] = {
    (NodeType.CONTEXT_SOURCE, NodeType.CAPABILITY),
    (NodeType.CONTEXT_SOURCE, NodeType.RESOURCE),
    (NodeType.AGENT, NodeType.RESOURCE),
    (NodeType.AGENT, NodeType.CAPABILITY),
    (NodeType.MCP_SERVER, NodeType.CAPABILITY),
    (NodeType.RESOURCE, NodeType.TOOL),
    (NodeType.CAPABILITY, NodeType.AGENT),
    (NodeType.RESOURCE, NodeType.CONTEXT_SOURCE),
}


class Edge(BaseModel, frozen=True):
    source_id: str
    target_id: str
    edge_type: EdgeType
    source_node_type: NodeType
    target_node_type: NodeType

    @model_validator(mode="after")
    def check_valid_relationship(self):
        key = (self.source_node_type, self.edge_type)
        allowed_targets = ALLOWED_RELATIONSHIPS.get(key)
        if allowed_targets is None or self.target_node_type not in allowed_targets:
            raise ValueError(
                f"Invalid edge: {self.source_node_type.value} "
                f"-[{self.edge_type.value}]-> "
                f"{self.target_node_type.value}"
            )
        return self


def is_invalid_relationship(source_type: NodeType, target_type: NodeType) -> bool:
    return (source_type, target_type) in INVALID_RELATIONSHIPS


def validate_edge_types(
    source_node_type: NodeType,
    edge_type: EdgeType,
    target_node_type: NodeType,
) -> bool:
    key = (source_node_type, edge_type)
    allowed_targets = ALLOWED_RELATIONSHIPS.get(key)
    return allowed_targets is not None and target_node_type in allowed_targets
