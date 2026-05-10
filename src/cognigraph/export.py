from __future__ import annotations

import json
from pathlib import Path

from cognigraph.graph.builder import CogniGraph
from cognigraph.schemas.enums import EdgeType, NodeType

_NODE_SHAPES: dict[NodeType, str] = {
    NodeType.CONTEXT_SOURCE: "parallelogram",
    NodeType.AGENT: "box",
    NodeType.TOOL: "component",
    NodeType.MCP_SERVER: "cylinder",
    NodeType.CAPABILITY: "diamond",
    NodeType.RESOURCE: "folder",
    NodeType.EXECUTION_ENVIRONMENT: "house",
}

_NODE_COLORS: dict[NodeType, str] = {
    NodeType.CONTEXT_SOURCE: "#f4a261",
    NodeType.AGENT: "#2a9d8f",
    NodeType.TOOL: "#264653",
    NodeType.MCP_SERVER: "#e76f51",
    NodeType.CAPABILITY: "#e63946",
    NodeType.RESOURCE: "#457b9d",
    NodeType.EXECUTION_ENVIRONMENT: "#a8dadc",
}


def to_dot(graph: CogniGraph, highlight_paths: list[list[str]] | None = None) -> str:
    highlight_edges: set[tuple[str, str]] = set()
    if highlight_paths:
        for path in highlight_paths:
            for i in range(len(path) - 1):
                highlight_edges.add((path[i], path[i + 1]))

    lines = [
        "digraph CogniGraph {",
        '  rankdir=LR;',
        '  node [style=filled, fontname="Helvetica"];',
        '  edge [fontname="Helvetica", fontsize=10];',
        "",
    ]

    for node_id, data in graph._graph.nodes(data=True):
        node_type = data.get("node_type", NodeType.TOOL)
        shape = _NODE_SHAPES.get(node_type, "ellipse")
        color = _NODE_COLORS.get(node_type, "#cccccc")
        label_parts = [node_id]
        if "trust_level" in data:
            label_parts.append(f"trust={data['trust_level']}")
        if "severity" in data:
            label_parts.append(f"sev={data['severity']}")
        if "sensitivity" in data:
            label_parts.append(f"sens={data['sensitivity']}")
        label = "\\n".join(label_parts)
        safe_id = node_id.replace("-", "_").replace(" ", "_")
        lines.append(
            f'  {safe_id} [label="{label}", shape={shape}, '
            f'fillcolor="{color}", fontcolor="white"];'
        )

    lines.append("")

    for src, tgt, data in graph._graph.edges(data=True):
        edge_type = data.get("edge_type", "")
        label = edge_type.value if isinstance(edge_type, EdgeType) else str(edge_type)
        safe_src = src.replace("-", "_").replace(" ", "_")
        safe_tgt = tgt.replace("-", "_").replace(" ", "_")
        style = ""
        if (src, tgt) in highlight_edges:
            style = ', color="red", penwidth=2.0'
        lines.append(f'  {safe_src} -> {safe_tgt} [label="{label}"{style}];')

    lines.append("}")
    return "\n".join(lines)


def to_json(graph: CogniGraph) -> dict:
    nodes = []
    for node_id, data in graph._graph.nodes(data=True):
        node = {"id": node_id}
        for k, v in data.items():
            if isinstance(v, NodeType):
                node[k] = v.value
            elif isinstance(v, EdgeType):
                node[k] = v.value
            else:
                node[k] = v
        nodes.append(node)

    edges = []
    for src, tgt, data in graph._graph.edges(data=True):
        edge = {"source": src, "target": tgt}
        for k, v in data.items():
            if isinstance(v, EdgeType):
                edge[k] = v.value
            else:
                edge[k] = v
        edges.append(edge)

    return {"nodes": nodes, "edges": edges}


def export_dot(graph: CogniGraph, path: Path, **kwargs: object) -> None:
    path.write_text(to_dot(graph, **kwargs))


def export_json(graph: CogniGraph, path: Path) -> None:
    path.write_text(json.dumps(to_json(graph), indent=2))
