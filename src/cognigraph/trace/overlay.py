from __future__ import annotations

from cognigraph.graph.builder import CogniGraph
from cognigraph.schemas.enums import EdgeType, RuntimeEdgeType
from cognigraph.trace.models import TraceLog

STATIC_TO_RUNTIME: dict[EdgeType, set[RuntimeEdgeType]] = {
    EdgeType.CONSUMED_BY: {
        RuntimeEdgeType.PASSED_TO,
        RuntimeEdgeType.RETRIEVED_FROM,
    },
    EdgeType.CAN_INVOKE: {RuntimeEdgeType.INVOKED},
    EdgeType.CAN_ACCESS_RESOURCE: {
        RuntimeEdgeType.READ_FROM,
        RuntimeEdgeType.WROTE_TO,
    },
    EdgeType.RUNS_IN: {RuntimeEdgeType.EXECUTED_IN},
}


class OverlayResult:
    def __init__(self) -> None:
        self.observed_edges: set[tuple[str, str, RuntimeEdgeType]] = set()
        self.unexpected_edges: list[tuple[str, str, RuntimeEdgeType]] = []
        self.unmatched_nodes: list[str] = []
        self.projected_paths: list[list[str]] = []

    @property
    def observed_count(self) -> int:
        return len(self.observed_edges)

    @property
    def unexpected_count(self) -> int:
        return len(self.unexpected_edges)

    @property
    def projected_count(self) -> int:
        return len(self.projected_paths)


def _runtime_matches_static(
    static_edge_type: EdgeType | None,
    runtime_edge_type: RuntimeEdgeType,
) -> bool:
    if static_edge_type is None:
        return False
    return runtime_edge_type in STATIC_TO_RUNTIME.get(static_edge_type, set())


def _mark_observed(
    graph: CogniGraph,
    source_id: str,
    target_id: str,
    runtime_edge_type: RuntimeEdgeType,
) -> None:
    graph._graph[source_id][target_id]["observed"] = True
    graph._graph[source_id][target_id]["runtime_edge_type"] = runtime_edge_type


def _project_tool_resource_event(
    graph: CogniGraph,
    source_id: str,
    target_id: str,
    runtime_edge_type: RuntimeEdgeType,
) -> list[list[str]]:
    if not _runtime_matches_static(EdgeType.CAN_ACCESS_RESOURCE, runtime_edge_type):
        return []

    paths: list[list[str]] = []
    for capability_id in graph.get_successors(source_id, EdgeType.EXPOSES_CAPABILITY):
        if target_id in graph.get_successors(capability_id, EdgeType.CAN_ACCESS_RESOURCE):
            _mark_observed(graph, source_id, capability_id, runtime_edge_type)
            _mark_observed(graph, capability_id, target_id, runtime_edge_type)
            paths.append([source_id, capability_id, target_id])
    return paths


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

        has_static = graph._graph.has_edge(event.source_id, event.target_id)
        if has_static:
            static_edge_type = graph._graph[event.source_id][event.target_id].get(
                "edge_type"
            )
            if _runtime_matches_static(static_edge_type, event.edge_type):
                result.observed_edges.add(edge_key)
                _mark_observed(
                    graph, event.source_id, event.target_id, event.edge_type
                )
            else:
                result.unexpected_edges.append(edge_key)
            continue

        projected_paths = _project_tool_resource_event(
            graph, event.source_id, event.target_id, event.edge_type
        )
        if projected_paths:
            result.observed_edges.add(edge_key)
            result.projected_paths.extend(projected_paths)
            continue

        result.unexpected_edges.append(edge_key)
        graph._graph.add_edge(
            event.source_id,
            event.target_id,
            edge_type=event.edge_type,
            runtime=True,
        )

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
