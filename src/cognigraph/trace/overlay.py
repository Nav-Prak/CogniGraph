from __future__ import annotations

from cognigraph.graph.builder import CogniGraph
from cognigraph.schemas.enums import EdgeType, RuntimeEdgeType
from cognigraph.trace.models import TraceLog

STATIC_TO_RUNTIME: dict[EdgeType, RuntimeEdgeType] = {
    EdgeType.CAN_INVOKE: RuntimeEdgeType.INVOKED,
    EdgeType.CAN_ACCESS_RESOURCE: RuntimeEdgeType.READ_FROM,
}


class OverlayResult:
    def __init__(self) -> None:
        self.observed_edges: set[tuple[str, str, RuntimeEdgeType]] = set()
        self.unexpected_edges: list[tuple[str, str, RuntimeEdgeType]] = []
        self.unmatched_nodes: list[str] = []

    @property
    def observed_count(self) -> int:
        return len(self.observed_edges)

    @property
    def unexpected_count(self) -> int:
        return len(self.unexpected_edges)


def apply_overlay(graph: CogniGraph, trace: TraceLog) -> OverlayResult:
    result = OverlayResult()
    graph_node_ids = {n for n, _ in graph._graph.nodes(data=True)}

    for event in trace.events:
        if event.source_id not in graph_node_ids:
            if event.source_id not in result.unmatched_nodes:
                result.unmatched_nodes.append(event.source_id)
            continue
        if event.target_id not in graph_node_ids:
            if event.target_id not in result.unmatched_nodes:
                result.unmatched_nodes.append(event.target_id)
            continue

        edge_key = (event.source_id, event.target_id, event.edge_type)
        result.observed_edges.add(edge_key)

        has_static = graph._graph.has_edge(event.source_id, event.target_id)
        if not has_static:
            result.unexpected_edges.append(edge_key)

        graph._graph.edges.get((event.source_id, event.target_id), {})
        if not graph._graph.has_edge(event.source_id, event.target_id):
            graph._graph.add_edge(
                event.source_id,
                event.target_id,
                edge_type=event.edge_type,
                runtime=True,
            )
        else:
            graph._graph[event.source_id][event.target_id]["observed"] = True
            graph._graph[event.source_id][event.target_id]["runtime_edge_type"] = event.edge_type

    return result


def get_exercised_static_edges(graph: CogniGraph) -> list[tuple[str, str]]:
    return [
        (src, tgt)
        for src, tgt, data in graph._graph.edges(data=True)
        if data.get("observed", False)
    ]


def get_unexercised_static_edges(graph: CogniGraph) -> list[tuple[str, str]]:
    return [
        (src, tgt)
        for src, tgt, data in graph._graph.edges(data=True)
        if not data.get("runtime", False) and not data.get("observed", False)
    ]


def get_runtime_only_edges(graph: CogniGraph) -> list[tuple[str, str]]:
    return [
        (src, tgt)
        for src, tgt, data in graph._graph.edges(data=True)
        if data.get("runtime", False)
    ]
