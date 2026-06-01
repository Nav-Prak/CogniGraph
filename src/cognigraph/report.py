from __future__ import annotations

import html
import json
import re
from pathlib import Path
from typing import Any

from cognigraph.graph.builder import CogniGraph
from cognigraph.schemas.enums import EdgeType, NodeType, RuntimeEdgeType
from cognigraph.schemas.findings import Finding, FindingSeverity

_SEVERITY_LABELS: dict[FindingSeverity, str] = {
    FindingSeverity.INFO: "INFO",
    FindingSeverity.LOW: "LOW",
    FindingSeverity.MEDIUM: "MEDIUM",
    FindingSeverity.HIGH: "HIGH",
    FindingSeverity.CRITICAL: "CRITICAL",
}


def format_finding(finding: Finding, index: int) -> str:
    severity = _SEVERITY_LABELS.get(finding.severity, "UNKNOWN")
    path_str = " -> ".join(finding.path)
    lines = [
        f"[{finding.rule_id}] [{severity}] {finding.title}",
        f"  {finding.description}",
        f"  Path: {path_str}",
        f"  Recommended control: {finding.recommended_control}",
    ]
    return "\n".join(lines)


def format_report(findings: list[Finding]) -> str:
    if not findings:
        return "No findings detected."

    by_severity: dict[FindingSeverity, int] = {}
    for f in findings:
        by_severity[f.severity] = by_severity.get(f.severity, 0) + 1

    lines = [
        f"CogniGraph Analysis Report",
        f"{'=' * 50}",
        f"Total findings: {len(findings)}",
    ]
    for sev in reversed(FindingSeverity):
        count = by_severity.get(sev, 0)
        if count:
            lines.append(f"  {_SEVERITY_LABELS[sev]}: {count}")
    lines.append(f"{'=' * 50}")
    lines.append("")

    for i, finding in enumerate(findings, 1):
        lines.append(f"--- Finding {i} ---")
        lines.append(format_finding(finding, i))
        lines.append("")

    return "\n".join(lines)


def findings_to_json(findings: list[Finding]) -> str:
    return json.dumps(
        [_finding_to_json_dict(f) for f in findings],
        indent=2,
    )


_RULE_EXPLANATIONS: dict[str, str] = {
    "R001": (
        "A low-trust context source can reach a high-severity capability through "
        "the declared agent and tool invocation graph."
    ),
    "R002": (
        "A low-trust context source can reach a sensitive resource through a "
        "capability binding."
    ),
    "R003": (
        "One agent can reach a dangerous capability pair. The risk comes from "
        "composition, even if each capability is expected in isolation."
    ),
    "R004": (
        "An MCP server backs high-impact tools reachable by multiple agents, "
        "which broadens the blast radius of that server."
    ),
    "R005": (
        "Low-trust context enters a higher-trust agent that has downstream access "
        "to a high-severity capability."
    ),
}


def _escape(value: object) -> str:
    return html.escape(str(value), quote=True)


def _anchor(prefix: str, value: str) -> str:
    slug = re.sub(r"[^A-Za-z0-9_-]+", "-", value).strip("-")
    return f"{prefix}-{slug or 'item'}"


def _enum_value(value: object) -> object:
    if isinstance(value, (FindingSeverity, NodeType, EdgeType, RuntimeEdgeType)):
        return value.value
    return value


def _edge_type_label(value: object) -> str:
    return str(_enum_value(value))


def _severity_counts(findings: list[Finding]) -> dict[FindingSeverity, int]:
    counts: dict[FindingSeverity, int] = {}
    for finding in findings:
        counts[finding.severity] = counts.get(finding.severity, 0) + 1
    return counts


def _finding_to_json_dict(finding: Finding) -> dict[str, Any]:
    data = finding.model_dump()
    data["severity"] = _SEVERITY_LABELS.get(finding.severity, "UNKNOWN")
    return data


def _node_type(graph: CogniGraph, node_id: str) -> str:
    data = graph.get_node(node_id)
    return str(_enum_value(data.get("node_type", "Unknown")))


def _safe_node(graph: CogniGraph, node_id: str) -> dict[str, Any] | None:
    try:
        return graph.get_node(node_id)
    except KeyError:
        return None


def _node_chip(graph: CogniGraph, node_id: str) -> str:
    node_type = _node_type(graph, node_id)
    css_type = _anchor("type", node_type).lower()
    return (
        f'<a class="node-chip {css_type}" href="#{_anchor("node", node_id)}">'
        f'<span>{_escape(node_id)}</span>'
        f'<small>{_escape(node_type)}</small>'
        "</a>"
    )


def _path_view(graph: CogniGraph, path: list[str]) -> str:
    parts: list[str] = []
    for index, node_id in enumerate(path):
        if index:
            parts.append('<span class="path-arrow">-&gt;</span>')
        parts.append(_node_chip(graph, node_id))
    return '<div class="path-view">' + "".join(parts) + "</div>"


def _finding_evidence(graph: CogniGraph, finding: Finding) -> str:
    items: list[str] = []
    for entity_key, label, attr_label, attr_name in [
        ("context_source", "Context source", "trust level", "trust_level"),
        ("agent", "Agent", "trust level", "trust_level"),
        ("capability", "Capability", "severity", "severity"),
        ("capability_a", "Capability A", "severity", "severity"),
        ("capability_b", "Capability B", "severity", "severity"),
        ("resource", "Resource", "sensitivity", "sensitivity"),
    ]:
        node_id = finding.entities.get(entity_key)
        if not node_id:
            continue
        data = _safe_node(graph, node_id)
        if data is None or attr_name not in data:
            continue
        items.append(
            f"<li><strong>{_escape(label)}:</strong> "
            f"<code>{_escape(node_id)}</code> "
            f"{_escape(attr_label)} {_escape(data[attr_name])}</li>"
        )

    if "mcp_server" in finding.entities:
        server_id = finding.entities["mcp_server"]
        items.append(
            f"<li><strong>MCP server:</strong> <code>{_escape(server_id)}</code></li>"
        )
    if "agent_count" in finding.entities:
        items.append(
            f"<li><strong>Agent exposure count:</strong> "
            f"{_escape(finding.entities['agent_count'])}</li>"
        )

    if not items:
        return ""
    return '<div class="evidence"><h4>Evidence</h4><ul>' + "".join(items) + "</ul></div>"


def _finding_card(graph: CogniGraph, finding: Finding, index: int) -> str:
    severity = _SEVERITY_LABELS.get(finding.severity, "UNKNOWN")
    explanation = _RULE_EXPLANATIONS.get(
        finding.rule_id,
        "This finding was produced by a configured CogniGraph detection rule.",
    )
    entity_items = "\n".join(
        f"<dt>{_escape(key)}</dt><dd>{_escape(value)}</dd>"
        for key, value in sorted(finding.entities.items())
    )
    return f"""
    <article class="finding-card severity-{severity.lower()}" id="{_anchor("finding", str(index))}">
      <div class="finding-head">
        <div>
          <p class="eyebrow">Finding {index}</p>
          <h3>{_escape(finding.title)}</h3>
        </div>
        <div class="badges">
          <span>{_escape(finding.rule_id)}</span>
          <span>{_escape(severity)}</span>
        </div>
      </div>
      <p>{_escape(finding.description)}</p>
      {_path_view(graph, finding.path)}
      {_finding_evidence(graph, finding)}
      <div class="recommended-control">
        <h4>Recommended Control</h4>
        <p>{_escape(finding.recommended_control)}</p>
      </div>
      <details>
        <summary>Explanation and entities</summary>
        <p>{_escape(explanation)}</p>
        <dl>{entity_items}</dl>
      </details>
    </article>
    """


def _node_table(graph: CogniGraph) -> str:
    rows = []
    for node_id, data in sorted(graph._graph.nodes(data=True), key=lambda item: item[0]):
        attrs = {
            key: _enum_value(value)
            for key, value in data.items()
            if key != "node_type"
        }
        attr_text = ", ".join(
            f"{key}={value}" for key, value in sorted(attrs.items())
        ) or "-"
        node_type = _enum_value(data.get("node_type", "Unknown"))
        rows.append(
            "<tr "
            f'id="{_anchor("node", node_id)}">'
            f"<td><code>{_escape(node_id)}</code></td>"
            f"<td>{_escape(node_type)}</td>"
            f"<td>{_escape(attr_text)}</td>"
            "</tr>"
        )
    return "\n".join(rows)


def _edge_table(graph: CogniGraph) -> str:
    rows = []
    for src, tgt, data in sorted(graph._graph.edges(data=True), key=lambda item: (item[0], item[1])):
        edge_type = _edge_type_label(data.get("edge_type", ""))
        tags = []
        if data.get("observed"):
            tags.append("observed")
        if data.get("runtime"):
            tags.append("runtime-only")
        if "runtime_edge_type" in data:
            tags.append(f"runtime={_edge_type_label(data['runtime_edge_type'])}")
        tag_text = ", ".join(tags) or "static"
        rows.append(
            "<tr>"
            f"<td><code>{_escape(src)}</code></td>"
            f"<td>{_escape(edge_type)}</td>"
            f"<td><code>{_escape(tgt)}</code></td>"
            f"<td>{_escape(tag_text)}</td>"
            "</tr>"
        )
    return "\n".join(rows)


def _overlay_summary_html(graph: CogniGraph, overlay_result: Any | None) -> str:
    if overlay_result is None:
        return ""

    exercised = [
        (src, tgt)
        for src, tgt, data in graph._graph.edges(data=True)
        if data.get("observed", False)
    ]
    unexercised = [
        (src, tgt)
        for src, tgt, data in graph._graph.edges(data=True)
        if not data.get("runtime", False) and not data.get("observed", False)
    ]
    runtime_only = [
        (src, tgt)
        for src, tgt, data in graph._graph.edges(data=True)
        if data.get("runtime", False)
    ]
    total_static = len(exercised) + len(unexercised)
    coverage = (len(exercised) / total_static * 100) if total_static else 0
    unmatched = getattr(overlay_result, "unmatched_nodes", [])
    unmatched_text = ", ".join(unmatched) if unmatched else "none"

    return f"""
    <section class="panel" id="runtime-overlay">
      <div class="section-head">
        <p class="eyebrow">Runtime Overlay</p>
        <h2>Observed vs. Possible Edges</h2>
      </div>
      <div class="metric-grid">
        <div><span>{getattr(overlay_result, "observed_count", 0)}</span><small>observed events</small></div>
        <div><span>{getattr(overlay_result, "projected_count", 0)}</span><small>projected paths</small></div>
        <div><span>{getattr(overlay_result, "unexpected_count", 0)}</span><small>unexpected events</small></div>
        <div><span>{len(runtime_only)}</span><small>runtime-only edges</small></div>
        <div><span>{coverage:.0f}%</span><small>Static edge coverage</small></div>
      </div>
      <p><strong>Unmatched nodes:</strong> {_escape(unmatched_text)}</p>
    </section>
    """


def format_html_report(
    graph: CogniGraph,
    findings: list[Finding],
    overlay_result: Any | None = None,
) -> str:
    counts = _severity_counts(findings)
    severity_cards = "\n".join(
        f"<div><span>{counts.get(sev, 0)}</span><small>{_escape(label.lower())}</small></div>"
        for sev, label in reversed(_SEVERITY_LABELS.items())
    )
    finding_cards = "\n".join(
        _finding_card(graph, finding, index)
        for index, finding in enumerate(findings, 1)
    ) or '<p class="empty-state">No findings detected.</p>'
    generated_summary = (
        f"{graph.node_count} nodes, {graph.edge_count} edges, {len(findings)} findings"
    )

    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>CogniGraph Analysis Report</title>
  <style>
    :root {{
      color-scheme: light;
      --ink: #17202a;
      --muted: #5f6b7a;
      --line: #d7dde5;
      --panel: #ffffff;
      --page: #f5f7fa;
      --accent: #1d7f73;
      --danger: #b42318;
      --warn: #a15c07;
      --info: #1d4ed8;
    }}
    * {{ box-sizing: border-box; }}
    body {{
      margin: 0;
      font-family: Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
      color: var(--ink);
      background: var(--page);
      line-height: 1.45;
    }}
    header {{
      padding: 32px clamp(20px, 5vw, 64px) 24px;
      background: #10212f;
      color: #f8fafc;
    }}
    header p {{ color: #c9d4df; max-width: 780px; }}
    main {{ padding: 24px clamp(20px, 5vw, 64px) 48px; }}
    h1, h2, h3 {{ margin: 0; line-height: 1.15; }}
    h1 {{ font-size: clamp(28px, 4vw, 44px); max-width: 980px; }}
    h2 {{ font-size: 22px; }}
    h3 {{ font-size: 18px; }}
    code {{
      background: #eef2f7;
      border-radius: 4px;
      padding: 1px 4px;
      font-family: "SFMono-Regular", Consolas, "Liberation Mono", monospace;
      font-size: 0.92em;
    }}
    .eyebrow {{
      margin: 0 0 6px;
      text-transform: uppercase;
      letter-spacing: 0.06em;
      color: var(--muted);
      font-size: 12px;
      font-weight: 700;
    }}
    header .eyebrow {{ color: #91b6c9; }}
    .panel, .finding-card {{
      background: var(--panel);
      border: 1px solid var(--line);
      border-radius: 8px;
      padding: 18px;
      box-shadow: 0 1px 2px rgba(16, 24, 40, 0.04);
      margin-bottom: 18px;
    }}
    .section-head {{
      display: flex;
      justify-content: space-between;
      gap: 16px;
      align-items: end;
      margin-bottom: 14px;
    }}
    .metric-grid {{
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
      gap: 12px;
      margin-top: 14px;
    }}
    .metric-grid div {{
      border: 1px solid var(--line);
      border-radius: 8px;
      padding: 14px;
      background: #fafbfd;
    }}
    .metric-grid span {{
      display: block;
      font-size: 26px;
      font-weight: 800;
      color: var(--accent);
    }}
    .metric-grid small {{ color: var(--muted); }}
    .finding-head {{
      display: flex;
      justify-content: space-between;
      gap: 14px;
      align-items: start;
      margin-bottom: 10px;
    }}
    .badges {{ display: flex; flex-wrap: wrap; gap: 6px; justify-content: end; }}
    .badges span {{
      border: 1px solid var(--line);
      border-radius: 999px;
      padding: 4px 8px;
      font-size: 12px;
      font-weight: 700;
      background: #f8fafc;
    }}
    .severity-critical {{ border-left: 5px solid var(--danger); }}
    .severity-high {{ border-left: 5px solid var(--warn); }}
    .severity-medium {{ border-left: 5px solid var(--info); }}
    .path-view {{
      display: flex;
      flex-wrap: wrap;
      gap: 8px;
      align-items: center;
      margin: 14px 0;
    }}
    .path-arrow {{ color: var(--muted); font-weight: 700; }}
    .node-chip {{
      display: inline-flex;
      flex-direction: column;
      gap: 1px;
      min-width: 118px;
      text-decoration: none;
      color: var(--ink);
      border: 1px solid var(--line);
      border-radius: 8px;
      padding: 8px 10px;
      background: #f8fafc;
    }}
    .node-chip span {{ font-weight: 700; }}
    .node-chip small {{ color: var(--muted); }}
    details {{
      border-top: 1px solid var(--line);
      margin-top: 12px;
      padding-top: 10px;
    }}
    h4 {{
      margin: 0 0 6px;
      font-size: 14px;
    }}
    .evidence, .recommended-control {{
      border: 1px solid var(--line);
      border-radius: 8px;
      padding: 12px;
      margin: 12px 0;
      background: #fafbfd;
    }}
    .evidence ul {{
      margin: 0;
      padding-left: 18px;
    }}
    .recommended-control p {{ margin: 0; color: var(--muted); }}
    summary {{ cursor: pointer; font-weight: 700; }}
    dl {{
      display: grid;
      grid-template-columns: minmax(120px, 180px) 1fr;
      gap: 6px 12px;
    }}
    dt {{ font-weight: 700; color: var(--muted); }}
    dd {{ margin: 0; }}
    .table-wrap {{ overflow-x: auto; }}
    table {{
      width: 100%;
      border-collapse: collapse;
      font-size: 14px;
    }}
    th, td {{
      border-bottom: 1px solid var(--line);
      padding: 9px 8px;
      text-align: left;
      vertical-align: top;
    }}
    th {{ color: var(--muted); font-size: 12px; text-transform: uppercase; letter-spacing: 0.04em; }}
    .empty-state {{
      color: var(--muted);
      border: 1px dashed var(--line);
      padding: 20px;
      border-radius: 8px;
      background: #fafbfd;
    }}
    @media print {{
      body {{ background: white; }}
      header {{ background: white; color: var(--ink); border-bottom: 1px solid var(--line); }}
      header p, header .eyebrow {{ color: var(--muted); }}
      .panel, .finding-card {{ break-inside: avoid; box-shadow: none; }}
    }}
  </style>
</head>
<body>
  <header>
    <p class="eyebrow">CogniGraph Static Report</p>
    <h1>Capability Reachability Analysis</h1>
    <p>{_escape(generated_summary)}. This report shows security findings, path evidence, node metadata, and graph edges from the analyzed fixture.</p>
  </header>
  <main>
    <section class="panel">
      <div class="section-head">
        <div>
          <p class="eyebrow">Summary</p>
          <h2>Findings by Severity</h2>
        </div>
      </div>
      <div class="metric-grid">
        <div><span>{len(findings)}</span><small>total findings</small></div>
        <div><span>{graph.node_count}</span><small>graph nodes</small></div>
        <div><span>{graph.edge_count}</span><small>graph edges</small></div>
        {severity_cards}
      </div>
    </section>

    {_overlay_summary_html(graph, overlay_result)}

    <section id="findings">
      <div class="section-head">
        <div>
          <p class="eyebrow">Path Viewer</p>
          <h2>Findings</h2>
        </div>
      </div>
      {finding_cards}
    </section>

    <section class="panel" id="node-metadata">
      <div class="section-head">
        <div>
          <p class="eyebrow">Node Metadata Inspector</p>
          <h2>Nodes</h2>
        </div>
      </div>
      <div class="table-wrap">
        <table>
          <thead><tr><th>ID</th><th>Type</th><th>Attributes</th></tr></thead>
          <tbody>{_node_table(graph)}</tbody>
        </table>
      </div>
    </section>

    <section class="panel" id="graph-edges">
      <div class="section-head">
        <div>
          <p class="eyebrow">Graph Export Preview</p>
          <h2>Edges</h2>
        </div>
      </div>
      <div class="table-wrap">
        <table>
          <thead><tr><th>Source</th><th>Edge</th><th>Target</th><th>Status</th></tr></thead>
          <tbody>{_edge_table(graph)}</tbody>
        </table>
      </div>
    </section>
  </main>
</body>
</html>
"""


def export_html_report(
    graph: CogniGraph,
    findings: list[Finding],
    path: Path,
    overlay_result: Any | None = None,
) -> None:
    path.write_text(
        format_html_report(graph, findings, overlay_result=overlay_result),
        encoding="utf-8",
    )
