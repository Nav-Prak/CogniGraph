from __future__ import annotations

import json
from pathlib import Path

from cognigraph.graph.builder import CogniGraph
from cognigraph.schemas.enums import EdgeType, NodeType, RuntimeEdgeType

_NODE_SHAPES: dict[NodeType, str] = {
    NodeType.CONTEXT_SOURCE: "parallelogram",
    NodeType.AGENT: "box",
    NodeType.TOOL: "component",
    NodeType.MCP_SERVER: "cylinder",
    NodeType.CAPABILITY: "diamond",
    NodeType.RESOURCE: "folder",
    NodeType.EXECUTION_ENVIRONMENT: "house",
    NodeType.POLICY: "octagon",
}

_NODE_COLORS: dict[NodeType, str] = {
    NodeType.CONTEXT_SOURCE: "#f4a261",
    NodeType.AGENT: "#2a9d8f",
    NodeType.TOOL: "#264653",
    NodeType.MCP_SERVER: "#e76f51",
    NodeType.CAPABILITY: "#e63946",
    NodeType.RESOURCE: "#457b9d",
    NodeType.EXECUTION_ENVIRONMENT: "#a8dadc",
    NodeType.POLICY: "#588157",
}


def _dot_escape(s: str) -> str:
    return s.replace("\\", "\\\\").replace('"', '\\"')


def _dot_id(node_id: str, node_type: NodeType) -> str:
    return f'"{_dot_escape(node_type.value)}:{_dot_escape(node_id)}"'


def _edge_label(data: dict) -> str:
    edge_type = data.get("edge_type", "")
    if isinstance(edge_type, (EdgeType, RuntimeEdgeType)):
        return edge_type.value
    return str(edge_type)


def _edge_style(src: str, tgt: str, data: dict, highlight_edges: set[tuple[str, str]]) -> str:
    is_runtime = data.get("runtime", False)
    is_observed = data.get("observed", False)
    is_highlight = (src, tgt) in highlight_edges

    parts: list[str] = []
    if is_runtime:
        parts.append('style="dashed"')
        parts.append('color="#e63946"')
    elif is_observed:
        parts.append('color="#2a9d8f"')
        parts.append("penwidth=2.5")
    elif is_highlight:
        parts.append('color="red"')
        parts.append("penwidth=2.0")

    return ", " + ", ".join(parts) if parts else ""


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
        label = _dot_escape("\\n".join(label_parts))
        did = _dot_id(node_id, node_type)
        lines.append(
            f'  {did} [label="{label}", shape={shape}, '
            f'fillcolor="{color}", fontcolor="white"];'
        )

    lines.append("")

    for src, tgt, data in graph._graph.edges(data=True):
        label = _dot_escape(_edge_label(data))
        src_type = graph._graph.nodes[src].get("node_type", NodeType.TOOL)
        tgt_type = graph._graph.nodes[tgt].get("node_type", NodeType.TOOL)
        src_did = _dot_id(src, src_type)
        tgt_did = _dot_id(tgt, tgt_type)
        style = _edge_style(src, tgt, data, highlight_edges)
        lines.append(f'  {src_did} -> {tgt_did} [label="{label}"{style}];')

    lines.append("}")
    return "\n".join(lines)


def to_json(graph: CogniGraph) -> dict:
    nodes = []
    for node_id, data in graph._graph.nodes(data=True):
        node = {"id": node_id}
        for k, v in data.items():
            if isinstance(v, (NodeType, EdgeType, RuntimeEdgeType)):
                node[k] = v.value
            else:
                node[k] = v
        nodes.append(node)

    edges = []
    for src, tgt, data in graph._graph.edges(data=True):
        edge = {"source": src, "target": tgt}
        for k, v in data.items():
            if isinstance(v, (EdgeType, RuntimeEdgeType)):
                edge[k] = v.value
            else:
                edge[k] = v
        edges.append(edge)

    return {"nodes": nodes, "edges": edges}


def export_dot(graph: CogniGraph, path: Path, **kwargs: object) -> None:
    path.write_text(to_dot(graph, **kwargs))


def export_json(graph: CogniGraph, path: Path) -> None:
    path.write_text(json.dumps(to_json(graph), indent=2))
