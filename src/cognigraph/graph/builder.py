from __future__ import annotations

import networkx as nx

from cognigraph.fixture.models import FixtureConfig
from cognigraph.schemas.edges import validate_edge_types
from cognigraph.schemas.enums import EdgeType, NodeType


class InvalidEdgeError(Exception):
    pass


class CogniGraph:
    def __init__(self) -> None:
        self._graph = nx.DiGraph()

    @property
    def node_count(self) -> int:
        return self._graph.number_of_nodes()

    @property
    def edge_count(self) -> int:
        return self._graph.number_of_edges()

    def add_node(self, node_id: str, node_type: NodeType, **attrs: object) -> None:
        self._graph.add_node(node_id, node_type=node_type, **attrs)

    def add_edge(
        self, source_id: str, target_id: str, edge_type: EdgeType
    ) -> None:
        src_data = self._graph.nodes.get(source_id)
        tgt_data = self._graph.nodes.get(target_id)
        if src_data is None:
            raise InvalidEdgeError(f"Source node '{source_id}' does not exist")
        if tgt_data is None:
            raise InvalidEdgeError(f"Target node '{target_id}' does not exist")
        src_type = src_data["node_type"]
        tgt_type = tgt_data["node_type"]
        if not validate_edge_types(src_type, edge_type, tgt_type):
            raise InvalidEdgeError(
                f"Invalid edge: {src_type.value} -[{edge_type.value}]-> {tgt_type.value}"
            )
        self._graph.add_edge(source_id, target_id, edge_type=edge_type)

    def get_node(self, node_id: str) -> dict:
        return dict(self._graph.nodes[node_id])

    def get_nodes_by_type(self, node_type: NodeType) -> list[str]:
        return [
            n for n, d in self._graph.nodes(data=True)
            if d.get("node_type") == node_type
        ]

    def get_successors(self, node_id: str, edge_type: EdgeType | None = None) -> list[str]:
        result = []
        for _, target, data in self._graph.out_edges(node_id, data=True):
            if edge_type is None or data.get("edge_type") == edge_type:
                result.append(target)
        return result

    def get_predecessors(self, node_id: str, edge_type: EdgeType | None = None) -> list[str]:
        result = []
        for source, _, data in self._graph.in_edges(node_id, data=True):
            if edge_type is None or data.get("edge_type") == edge_type:
                result.append(source)
        return result

    def get_reachable_with_paths(
        self, start_id: str, max_depth: int
    ) -> dict[str, list[str]]:
        paths: dict[str, list[str]] = {}
        queue: list[tuple[str, int, list[str]]] = [(start_id, 0, [start_id])]
        visited: set[str] = set()
        while queue:
            current, depth, path = queue.pop(0)
            if current in visited:
                continue
            visited.add(current)
            if current != start_id:
                paths[current] = path
            if depth < max_depth:
                for succ in self.get_successors(current, EdgeType.CAN_INVOKE):
                    if succ not in visited:
                        queue.append((succ, depth + 1, path + [succ]))
        return paths

    def get_capabilities_of_tool(self, tool_id: str) -> list[str]:
        return self.get_successors(tool_id, EdgeType.EXPOSES_CAPABILITY)

    def get_resources_of_capability(self, capability_id: str) -> list[str]:
        return self.get_successors(capability_id, EdgeType.CAN_ACCESS_RESOURCE)

    def get_agents_reaching_tool(self, tool_id: str, max_depth: int) -> set[str]:
        agents: set[str] = set()
        for agent_id in self.get_nodes_by_type(NodeType.AGENT):
            reachable = self.get_reachable_with_paths(agent_id, max_depth)
            if tool_id in reachable:
                agents.add(agent_id)
        return agents


def build_from_fixture(config: FixtureConfig) -> CogniGraph:
    graph = CogniGraph()

    for cs in config.context_sources:
        graph.add_node(
            cs.id, NodeType.CONTEXT_SOURCE,
            trust_level=cs.trust_level, source_type=cs.source_type.value,
        )

    for agent in config.agents:
        graph.add_node(
            agent.id, NodeType.AGENT,
            trust_level=agent.trust_level,
        )

    for tool in config.tools:
        graph.add_node(
            tool.id, NodeType.TOOL,
            mcp_server=tool.mcp_server,
        )

    for server in config.mcp_servers:
        graph.add_node(server.id, NodeType.MCP_SERVER)

    for cap in config.capabilities:
        graph.add_node(
            cap.id, NodeType.CAPABILITY,
            severity=cap.severity,
            resource_binding_required=cap.resource_binding_required,
        )

    for res in config.resources:
        graph.add_node(
            res.id, NodeType.RESOURCE,
            resource_type=res.type.value, sensitivity=res.sensitivity,
        )

    for agent in config.agents:
        for cs_id in agent.consumes:
            graph.add_edge(cs_id, agent.id, EdgeType.CONSUMED_BY)
        for tool_id in agent.can_invoke:
            graph.add_edge(agent.id, tool_id, EdgeType.CAN_INVOKE)

    for tool in config.tools:
        for invoked_id in tool.can_invoke:
            graph.add_edge(tool.id, invoked_id, EdgeType.CAN_INVOKE)
        for cap_id in tool.capabilities:
            graph.add_edge(tool.id, cap_id, EdgeType.EXPOSES_CAPABILITY)
        if tool.mcp_server:
            graph.add_edge(tool.id, tool.mcp_server, EdgeType.USES_SERVER)

    for binding in config.capability_bindings:
        graph.add_edge(
            binding.capability, binding.resource, EdgeType.CAN_ACCESS_RESOURCE
        )

    for policy in config.policies:
        graph.add_node(
            policy.id, NodeType.POLICY,
            effect=policy.effect.value, description=policy.description,
        )
        for target_id in policy.applies_to:
            graph.add_edge(policy.id, target_id, EdgeType.APPLIES_TO)

    return graph
