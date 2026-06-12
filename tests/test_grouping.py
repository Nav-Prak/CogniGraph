from datetime import date, timedelta
from pathlib import Path

import pytest
import yaml

from cognigraph.cli import main
from cognigraph.fixture.loader import load_fixture
from cognigraph.graph.builder import build_from_fixture
from cognigraph.report import format_group_summary
from cognigraph.rules.engine import run_all_rules
from cognigraph.rules.grouping import (
    SuppressionError,
    active_groups,
    apply_suppressions,
    group_findings,
    group_target,
    load_suppressions,
    rank_groups,
    suppressed_groups,
)
from cognigraph.schemas.findings import Finding, FindingSeverity, Suppression

EXAMPLES_DIR = Path(__file__).resolve().parent.parent / "examples"
VULNERABLE = EXAMPLES_DIR / "rag_mcp_vulnerable.yaml"


def vulnerable_findings():
    config = load_fixture(VULNERABLE)
    graph = build_from_fixture(config)
    return run_all_rules(graph, config.analysis, config.policy)


def make_finding(rule_id="R001", capability="SecretRead", path=None):
    return Finding(
        rule_id=rule_id,
        title="t",
        description="d",
        severity=FindingSeverity.HIGH,
        path=path or ["a", "b"],
        entities={"capability": capability},
        recommended_control="c",
    )


class TestGrouping:
    def test_vulnerable_demo_groups_by_rule_and_target(self):
        findings = vulnerable_findings()
        groups = group_findings(findings)
        assert len(groups) <= len(findings)
        assert sum(len(g.findings) for g in groups) == len(findings)
        keys = [(g.rule_id, g.target) for g in groups]
        assert len(keys) == len(set(keys))
        for group in groups:
            for finding in group.findings:
                assert finding.rule_id == group.rule_id
                assert group_target(finding) == group.target

    def test_multiple_paths_to_same_target_form_one_group(self):
        findings = [
            make_finding(capability="SecretRead", path=["web", "agent", "t1"]),
            make_finding(capability="SecretRead", path=["mail", "agent", "t2"]),
            make_finding(capability="GitHubPush", path=["web", "agent", "t3"]),
        ]
        groups = group_findings(findings)
        assert len(groups) == 2
        by_target = {g.target: g for g in groups}
        assert len(by_target["SecretRead"].findings) == 2
        assert len(by_target["GitHubPush"].findings) == 1

    def test_group_severity_is_max_of_members(self):
        findings = vulnerable_findings()
        for group in group_findings(findings):
            assert group.severity == max(f.severity for f in group.findings)

    def test_r003_target_is_capability_pair(self):
        finding = Finding(
            rule_id="R003",
            title="t",
            description="d",
            severity=FindingSeverity.HIGH,
            path=["a", "x", "y"],
            entities={"agent": "a", "capability_a": "X", "capability_b": "Y"},
            recommended_control="c",
        )
        assert group_target(finding) == "X+Y"

    def test_unknown_rule_falls_back_to_path_end(self):
        finding = make_finding(rule_id="R999", path=["a", "b", "z"])
        assert group_target(finding) == "z"

    def test_groups_sorted(self):
        groups = group_findings(vulnerable_findings())
        assert groups == sorted(groups, key=lambda g: (g.rule_id, g.target))


class TestRanking:
    def make(self, rule_id, capability, severity, path):
        return Finding(
            rule_id=rule_id,
            title="t",
            description="d",
            severity=severity,
            path=path,
            entities={"capability": capability},
            recommended_control="c",
        )

    def test_severity_outranks_path_length(self):
        groups = group_findings(
            [
                self.make("R001", "LongCritical", FindingSeverity.CRITICAL,
                          ["a", "b", "c", "d", "e"]),
                self.make("R001", "ShortHigh", FindingSeverity.HIGH, ["a", "b"]),
            ]
        )
        ranked = rank_groups(groups)
        assert [g.target for g in ranked] == ["LongCritical", "ShortHigh"]

    def test_shorter_path_ranks_first_within_severity(self):
        groups = group_findings(
            [
                self.make("R001", "Long", FindingSeverity.HIGH,
                          ["a", "b", "c", "d"]),
                self.make("R001", "Short", FindingSeverity.HIGH, ["a", "b"]),
            ]
        )
        ranked = rank_groups(groups)
        assert [g.target for g in ranked] == ["Short", "Long"]

    def test_lower_source_trust_ranks_first_with_graph(self):
        from cognigraph.fixture.models import FixtureConfig

        config = FixtureConfig(
            **{
                "context_sources": [
                    {"id": "web", "source_type": "webpage", "trust_level": 0},
                    {"id": "memory", "source_type": "memory", "trust_level": 2},
                ],
                "agents": [
                    {"id": "agent", "trust_level": 2,
                     "consumes": ["web", "memory"], "can_invoke": []}
                ],
            }
        )
        graph = build_from_fixture(config)
        findings = [
            Finding(
                rule_id="R001", title="t", description="d",
                severity=FindingSeverity.HIGH, path=["a", "b"],
                entities={"capability": "ViaMemory",
                          "context_source": "memory"},
                recommended_control="c",
            ),
            Finding(
                rule_id="R001", title="t", description="d",
                severity=FindingSeverity.HIGH, path=["a", "b"],
                entities={"capability": "ViaWeb", "context_source": "web"},
                recommended_control="c",
            ),
        ]
        ranked = rank_groups(group_findings(findings), graph)
        assert [g.target for g in ranked] == ["ViaWeb", "ViaMemory"]

    def test_unknown_source_node_is_neutral(self):
        config = load_fixture(VULNERABLE)
        graph = build_from_fixture(config)
        finding = Finding(
            rule_id="R001", title="t", description="d",
            severity=FindingSeverity.HIGH, path=["a", "b"],
            entities={"capability": "X", "context_source": "ghost"},
            recommended_control="c",
        )
        ranked = rank_groups(group_findings([finding]), graph)
        assert len(ranked) == 1

    def test_vulnerable_demo_ranked_critical_first(self):
        config = load_fixture(VULNERABLE)
        graph = build_from_fixture(config)
        ranked = rank_groups(group_findings(vulnerable_findings()), graph)
        severities = [g.severity for g in ranked]
        assert severities == sorted(severities, reverse=True)


class TestSuppressions:
    def test_suppress_marks_group(self):
        groups = group_findings([make_finding()])
        result = apply_suppressions(
            groups,
            [Suppression(rule_id="R001", target="SecretRead", reason="accepted")],
        )
        assert suppressed_groups(result)[0].suppression_reason == "accepted"
        assert active_groups(result) == []

    def test_unmatched_suppression_errors(self):
        groups = group_findings([make_finding()])
        with pytest.raises(SuppressionError, match="matches no finding group"):
            apply_suppressions(
                groups,
                [Suppression(rule_id="R001", target="Nope", reason="r")],
            )

    def test_expired_suppression_errors(self):
        groups = group_findings([make_finding()])
        expired = Suppression(
            rule_id="R001",
            target="SecretRead",
            reason="r",
            expires=date.today() - timedelta(days=1),
        )
        with pytest.raises(SuppressionError, match="expired on"):
            apply_suppressions(groups, [expired])

    def test_future_expiry_is_fine(self):
        groups = group_findings([make_finding()])
        future = Suppression(
            rule_id="R001",
            target="SecretRead",
            reason="r",
            expires=date.today() + timedelta(days=30),
        )
        result = apply_suppressions(groups, [future])
        assert len(suppressed_groups(result)) == 1

    def test_load_suppressions_file(self, tmp_path):
        path = tmp_path / "sup.yaml"
        path.write_text(
            yaml.safe_dump(
                {
                    "suppressions": [
                        {
                            "rule_id": "R001",
                            "target": "SecretRead",
                            "reason": "vault access is approval-gated",
                            "expires": "2099-01-01",
                        }
                    ]
                }
            ),
            encoding="utf-8",
        )
        sups = load_suppressions(path)
        assert sups[0].target == "SecretRead"
        assert sups[0].expires == date(2099, 1, 1)

    def test_load_empty_file(self, tmp_path):
        path = tmp_path / "sup.yaml"
        path.write_text("", encoding="utf-8")
        assert load_suppressions(path) == []

    def test_load_missing_file_errors(self, tmp_path):
        with pytest.raises(SuppressionError, match="Could not read"):
            load_suppressions(tmp_path / "nope.yaml")

    def test_load_non_mapping_errors(self, tmp_path):
        path = tmp_path / "sup.yaml"
        path.write_text("- just\n- a list\n", encoding="utf-8")
        with pytest.raises(SuppressionError, match="Expected a mapping"):
            load_suppressions(path)

    def test_load_invalid_schema_errors(self, tmp_path):
        path = tmp_path / "sup.yaml"
        path.write_text(
            yaml.safe_dump({"suppressions": [{"rule_id": "R001"}]}),
            encoding="utf-8",
        )
        with pytest.raises(SuppressionError, match="Invalid suppressions"):
            load_suppressions(path)


def write_full_suppressions(tmp_path: Path) -> Path:
    groups = group_findings(vulnerable_findings())
    path = tmp_path / "suppressions.yaml"
    path.write_text(
        yaml.safe_dump(
            {
                "suppressions": [
                    {
                        "rule_id": g.rule_id,
                        "target": g.target,
                        "reason": "accepted for test",
                    }
                    for g in groups
                ]
            }
        ),
        encoding="utf-8",
    )
    return path


class TestCLISuppressions:
    def test_suppressing_all_groups_exits_zero(self, tmp_path, capsys):
        sup = write_full_suppressions(tmp_path)
        rc = main([str(VULNERABLE), "--suppressions", str(sup)])
        out = capsys.readouterr().out
        assert rc == 0
        assert "Accepted Risks" in out
        assert "accepted for test" in out

    def test_partial_suppression_still_fails(self, tmp_path, capsys):
        groups = group_findings(vulnerable_findings())
        path = tmp_path / "sup.yaml"
        path.write_text(
            yaml.safe_dump(
                {
                    "suppressions": [
                        {
                            "rule_id": groups[0].rule_id,
                            "target": groups[0].target,
                            "reason": "one accepted",
                        }
                    ]
                }
            ),
            encoding="utf-8",
        )
        rc = main([str(VULNERABLE), "--suppressions", str(path), "--quiet"])
        assert rc == 2

    def test_stale_suppression_exits_one(self, tmp_path, capsys):
        path = tmp_path / "sup.yaml"
        path.write_text(
            yaml.safe_dump(
                {
                    "suppressions": [
                        {"rule_id": "R001", "target": "Nope", "reason": "stale"}
                    ]
                }
            ),
            encoding="utf-8",
        )
        rc = main([str(VULNERABLE), "--suppressions", str(path), "--quiet"])
        assert rc == 1
        assert "matches no finding group" in capsys.readouterr().err

    def test_group_summary_printed(self, capsys):
        rc = main([str(VULNERABLE)])
        out = capsys.readouterr().out
        assert rc == 2
        assert "--- Finding Groups ---" in out
        assert "Active groups:" in out

    def test_group_summary_format(self):
        groups = group_findings(vulnerable_findings())
        text = format_group_summary(groups)
        assert "Active groups:" in text
        assert "path(s)" in text


class TestHtmlGroupPanel:
    def test_html_report_includes_group_panel(self, tmp_path, capsys):
        report_path = tmp_path / "report.html"
        rc = main([str(VULNERABLE), "--quiet", "--html-report", str(report_path)])
        assert rc == 2
        content = report_path.read_text(encoding="utf-8")
        assert "Finding Groups" in content
        assert 'group-badge active' in content

    def test_html_report_shows_suppressed_badge(self, tmp_path, capsys):
        sup = write_full_suppressions(tmp_path)
        report_path = tmp_path / "report.html"
        rc = main(
            [
                str(VULNERABLE),
                "--quiet",
                "--suppressions",
                str(sup),
                "--html-report",
                str(report_path),
            ]
        )
        assert rc == 0
        content = report_path.read_text(encoding="utf-8")
        assert 'group-badge suppressed' in content
        assert "accepted for test" in content
        assert 'group-badge active' not in content

    def test_html_report_shows_mitigated_badge(self, tmp_path, capsys):
        import yaml as yaml_mod

        fixture = {
            "context_sources": [
                {"id": "web", "source_type": "webpage", "trust_level": 0}
            ],
            "agents": [
                {
                    "id": "agent",
                    "trust_level": 2,
                    "consumes": ["web"],
                    "can_invoke": ["tool_a"],
                }
            ],
            "tools": [{"id": "tool_a", "capabilities": ["CapA"]}],
            "capabilities": [{"id": "CapA", "severity": 4}],
            "policies": [{"id": "gate", "applies_to": ["tool_a"]}],
        }
        fixture_path = tmp_path / "f.yaml"
        fixture_path.write_text(yaml_mod.safe_dump(fixture), encoding="utf-8")
        report_path = tmp_path / "report.html"
        rc = main(
            [str(fixture_path), "--quiet", "--html-report", str(report_path)]
        )
        assert rc == 0
        content = report_path.read_text(encoding="utf-8")
        assert 'group-badge mitigated' in content
        assert "policy &#x27;gate&#x27;" in content

    def test_html_report_without_groups_param_unchanged(self):
        from cognigraph.report import format_html_report

        config = load_fixture(VULNERABLE)
        graph = build_from_fixture(config)
        html = format_html_report(graph, [])
        assert "Finding Groups" not in html


class TestFailOn:
    def test_fail_on_critical_with_only_high_groups(self, tmp_path):
        # Agent trust 1 keeps R005 (always CRITICAL) out of the picture;
        # the severity-3 capability yields an R001 group at HIGH only.
        fixture = {
            "context_sources": [
                {"id": "web", "source_type": "webpage", "trust_level": 0}
            ],
            "agents": [
                {
                    "id": "agent",
                    "trust_level": 1,
                    "consumes": ["web"],
                    "can_invoke": ["tool_a"],
                }
            ],
            "tools": [{"id": "tool_a", "capabilities": ["CapA"]}],
            "capabilities": [{"id": "CapA", "severity": 3}],
        }
        path = tmp_path / "f.yaml"
        path.write_text(yaml.safe_dump(fixture), encoding="utf-8")
        assert main([str(path), "--quiet"]) == 2
        assert main([str(path), "--quiet", "--fail-on", "high"]) == 2
        assert main([str(path), "--quiet", "--fail-on", "critical"]) == 0

    def test_fail_on_any_default_unchanged(self):
        assert main([str(VULNERABLE), "--quiet"]) == 2
        assert main([str(VULNERABLE), "--quiet", "--fail-on", "critical"]) == 2

    def test_safe_fixture_exits_zero_at_any(self):
        safe = EXAMPLES_DIR / "least_privilege_safe.yaml"
        assert main([str(safe), "--quiet", "--fail-on", "any"]) == 0
