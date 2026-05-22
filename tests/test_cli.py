import json
from pathlib import Path

from cognigraph.cli import main

FIXTURES_DIR = Path(__file__).resolve().parent.parent / "fixtures"
SAMPLE = str(FIXTURES_DIR / "sample_fixture.yaml")


class TestCLI:
    def test_runs_and_returns_2_on_findings(self):
        rc = main([SAMPLE, "--quiet"])
        assert rc == 2

    def test_prints_report(self, capsys):
        main([SAMPLE])
        out = capsys.readouterr().out
        assert "CogniGraph Analysis Report" in out
        assert "[R001]" in out
        assert "Total findings:" in out

    def test_quiet_suppresses_report(self, capsys):
        main([SAMPLE, "--quiet"])
        out = capsys.readouterr().out
        assert out == ""

    def test_export_dot(self, tmp_path):
        dot_path = tmp_path / "graph.dot"
        main([SAMPLE, "--quiet", "--export-dot", str(dot_path)])
        content = dot_path.read_text()
        assert "digraph CogniGraph" in content
        assert "planner_agent" in content

    def test_export_json(self, tmp_path):
        json_path = tmp_path / "graph.json"
        main([SAMPLE, "--quiet", "--export-json", str(json_path)])
        data = json.loads(json_path.read_text())
        assert len(data["nodes"]) == 12
        assert len(data["edges"]) == 11

    def test_findings_json(self, tmp_path):
        json_path = tmp_path / "findings.json"
        main([SAMPLE, "--quiet", "--findings-json", str(json_path)])
        findings = json.loads(json_path.read_text())
        assert len(findings) == 11

    def test_html_report(self, tmp_path):
        html_path = tmp_path / "report.html"
        main([SAMPLE, "--quiet", "--html-report", str(html_path)])
        content = html_path.read_text()
        assert "CogniGraph Static Report" in content
        assert "Path Viewer" in content
        assert "Node Metadata Inspector" in content
        assert "external_webpage" in content

    def test_bad_fixture_returns_1(self, tmp_path):
        bad = tmp_path / "bad.yaml"
        bad.write_text("agents:\n  - id: a\n    trust_level: 99\n")
        rc = main([str(bad), "--quiet"])
        assert rc == 1

    def test_missing_fixture_returns_1(self):
        rc = main(["nonexistent.yaml", "--quiet"])
        assert rc == 1
