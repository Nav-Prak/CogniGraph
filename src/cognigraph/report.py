from __future__ import annotations

import json

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
        [f.model_dump() for f in findings],
        indent=2,
        default=str,
    )
