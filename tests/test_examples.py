from pathlib import Path

from cognigraph.fixture.loader import load_fixture
from cognigraph.graph.builder import build_from_fixture
from cognigraph.report import findings_to_json, format_html_report
from cognigraph.rules.engine import run_all_rules

EXAMPLES_DIR = Path(__file__).resolve().parent.parent / "examples"


def _run_example(name: str, annotations: str | None = None):
    annotations_path = EXAMPLES_DIR / annotations if annotations else None
    config = load_fixture(EXAMPLES_DIR / name, annotations_path=annotations_path)
    graph = build_from_fixture(config)
    findings = run_all_rules(graph, config.analysis)
    return config, graph, findings


def _by_rule(findings):
    grouped = {}
    for finding in findings:
        grouped.setdefault(finding.rule_id, []).append(finding)
    return grouped


class TestMVPExamples:
    def test_vulnerable_fixture_produces_expected_findings(self):
        _, _, findings = _run_example("rag_mcp_vulnerable.yaml")
        grouped = _by_rule(findings)

        assert len(grouped["R001"]) == 4
        assert len(grouped["R002"]) == 2
        assert len(grouped["R003"]) == 1
        assert "R004" not in grouped
        assert len(grouped["R005"]) == 4

        r001_caps = {f.entities["capability"] for f in grouped["R001"]}
        assert r001_caps == {
            "SecretRead",
            "FilesystemRead",
            "GitHubPush",
            "ExternalNetworkSend",
        }
        assert all(f.recommended_control for f in findings)

    def test_manual_annotations_produce_same_vulnerable_findings(self):
        _, _, inline_findings = _run_example("rag_mcp_vulnerable.yaml")
        _, _, annotated_findings = _run_example(
            "rag_mcp_unannotated.yaml",
            annotations="manual_tool_annotations.yaml",
        )
        assert [f.model_dump() for f in annotated_findings] == [
            f.model_dump() for f in inline_findings
        ]

    def test_safe_fixture_produces_no_findings(self):
        _, _, findings = _run_example("least_privilege_safe.yaml")
        assert findings == []

    def test_overexposed_mcp_fixture_triggers_r004(self):
        config, _, findings = _run_example("overexposed_mcp.yaml")
        assert config.analysis.overexposure_agent_threshold == 3
        assert len(findings) == 1

        finding = findings[0]
        assert finding.rule_id == "R004"
        assert finding.entities["mcp_server"] == "critical_ops_mcp"
        assert finding.entities["agent_count"] == "3"
        assert finding.path == [
            "critical_ops_mcp",
            "deployment_agent",
            "incident_agent",
            "maintenance_agent",
        ]

    def test_vulnerable_json_includes_recommended_control(self):
        _, _, findings = _run_example("rag_mcp_vulnerable.yaml")
        raw = findings_to_json(findings)
        assert '"recommended_control"' in raw
        assert '"severity": "CRITICAL"' in raw
        assert "Restrict low-trust context" in raw

    def test_vulnerable_html_includes_evidence_and_control(self):
        _, graph, findings = _run_example("rag_mcp_vulnerable.yaml")
        html = format_html_report(graph, findings)
        assert "Recommended Control" in html
        assert "Evidence" in html
        assert "research_planner" in html
        assert "severity 4" in html
        assert "sensitivity 4" in html
