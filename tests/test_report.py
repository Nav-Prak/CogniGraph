import json

from cognigraph.report import (
    findings_to_json,
    format_finding,
    format_html_report,
    format_report,
)
from cognigraph.rules.engine import run_all_rules
from cognigraph.schemas.findings import Finding, FindingSeverity


def _make_finding(**overrides) -> Finding:
    defaults = {
        "rule_id": "R001",
        "title": "Test finding",
        "description": "A test finding",
        "severity": FindingSeverity.HIGH,
        "path": ["a", "b", "c"],
        "entities": {"agent": "a"},
        "recommended_control": "Do the safer thing.",
    }
    defaults.update(overrides)
    return Finding(**defaults)


class TestFormatFinding:
    def test_contains_rule_id(self):
        f = _make_finding()
        text = format_finding(f, 1)
        assert "[R001]" in text

    def test_contains_severity(self):
        f = _make_finding(severity=FindingSeverity.CRITICAL)
        text = format_finding(f, 1)
        assert "[CRITICAL]" in text

    def test_contains_path(self):
        f = _make_finding(path=["x", "y", "z"])
        text = format_finding(f, 1)
        assert "x -> y -> z" in text

    def test_contains_description(self):
        f = _make_finding(description="something bad")
        text = format_finding(f, 1)
        assert "something bad" in text

    def test_contains_recommended_control(self):
        f = _make_finding(recommended_control="Restrict the risky edge.")
        text = format_finding(f, 1)
        assert "Recommended control: Restrict the risky edge." in text


class TestFormatReport:
    def test_empty_findings(self):
        report = format_report([])
        assert "No findings" in report

    def test_summary_header(self):
        findings = [_make_finding(), _make_finding(rule_id="R002")]
        report = format_report(findings)
        assert "Total findings: 2" in report

    def test_severity_counts(self):
        findings = [
            _make_finding(severity=FindingSeverity.CRITICAL),
            _make_finding(severity=FindingSeverity.CRITICAL),
            _make_finding(severity=FindingSeverity.HIGH),
        ]
        report = format_report(findings)
        assert "CRITICAL: 2" in report
        assert "HIGH: 1" in report

    def test_each_finding_listed(self):
        findings = [
            _make_finding(rule_id="R001"),
            _make_finding(rule_id="R003"),
        ]
        report = format_report(findings)
        assert "Finding 1" in report
        assert "Finding 2" in report
        assert "[R001]" in report
        assert "[R003]" in report


class TestFindingsToJson:
    def test_valid_json(self):
        findings = [_make_finding()]
        raw = findings_to_json(findings)
        parsed = json.loads(raw)
        assert isinstance(parsed, list)
        assert len(parsed) == 1

    def test_fields_present(self):
        findings = [_make_finding()]
        parsed = json.loads(findings_to_json(findings))
        entry = parsed[0]
        assert entry["rule_id"] == "R001"
        assert entry["title"] == "Test finding"
        assert entry["severity"] == "HIGH"
        assert entry["path"] == ["a", "b", "c"]
        assert entry["recommended_control"] == "Do the safer thing."


class TestFormatHtmlReport:
    def test_contains_phase3_sections(self, sample_graph, sample_config):
        findings = run_all_rules(sample_graph, sample_config.analysis)
        html = format_html_report(sample_graph, findings)
        assert "Graph Visualizer" in html
        assert "Capability Map" in html
        assert "Path Viewer" in html
        assert "Node Metadata Inspector" in html
        assert "Graph Export Preview" in html
        assert "Finding 1" in html

    def test_contains_path_and_node_metadata(self, sample_graph, sample_config):
        findings = run_all_rules(sample_graph, sample_config.analysis)
        html = format_html_report(sample_graph, findings)
        assert "external_webpage" in html
        assert "planner_agent" in html
        assert "filesystem_tool" in html
        assert "SecretRead" in html
        assert "trust_level=2" in html
        assert "Recommended Control" in html
        assert "Restrict low-trust context" in html

    def test_contains_inline_graph_visualizer(self, sample_graph, sample_config):
        findings = run_all_rules(sample_graph, sample_config.analysis)
        html = format_html_report(sample_graph, findings)
        assert '<svg class="graph-svg"' in html
        assert 'data-node-id="external_webpage"' in html
        assert 'data-node-id="SecretRead"' in html
        assert "finding-edge" in html
        assert "CONSUMED_BY" in html
        assert "CAN_INVOKE" in html

    def test_escapes_finding_content(self, sample_graph):
        finding = _make_finding(
            title="<script>",
            description='bad "thing"',
            path=["external_webpage", "planner_agent"],
        )
        html = format_html_report(sample_graph, [finding])
        assert "&lt;script&gt;" in html
        assert 'bad &quot;thing&quot;' in html
