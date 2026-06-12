from pathlib import Path

import pytest
import yaml

from cognigraph.fixture.loader import load_fixture
from cognigraph.fixture.models import (
    DEFAULT_DANGEROUS_PAIRS,
    AnalysisConfig,
    ContextSourceConfig,
    FixtureConfig,
    PolicyConfig,
)
from cognigraph.graph.builder import build_from_fixture
from cognigraph.rules.engine import run_all_rules

FIXTURES_DIR = Path(__file__).resolve().parent.parent / "fixtures"


def make_fixture(**overrides) -> FixtureConfig:
    data = {
        "context_sources": [
            {"id": "web", "source_type": "webpage", "trust_level": 0}
        ],
        "agents": [
            {
                "id": "agent",
                "trust_level": 2,
                "consumes": ["web"],
                "can_invoke": ["tool_a", "tool_b"],
            }
        ],
        "tools": [
            {"id": "tool_a", "capabilities": ["CapA"]},
            {"id": "tool_b", "capabilities": ["CapB"]},
        ],
        "capabilities": [
            {"id": "CapA", "severity": 2},
            {"id": "CapB", "severity": 2},
        ],
    }
    data.update(overrides)
    return FixtureConfig(**data)


class TestPolicyDefaults:
    def test_default_policy_matches_legacy_constants(self):
        policy = PolicyConfig()
        assert policy.critical_severity == 3
        assert policy.sensitive_sensitivity == 3
        assert policy.low_trust_max == 1
        assert policy.dangerous_pairs == [
            tuple(pair) for pair in DEFAULT_DANGEROUS_PAIRS
        ]

    def test_sample_fixture_findings_unchanged_with_explicit_default_policy(self):
        config = load_fixture(FIXTURES_DIR / "sample_fixture.yaml")
        graph = build_from_fixture(config)
        without_policy = run_all_rules(graph, config.analysis)
        with_policy = run_all_rules(graph, config.analysis, PolicyConfig())
        assert without_policy == with_policy

    def test_fixture_without_policy_block_gets_defaults(self):
        config = load_fixture(FIXTURES_DIR / "sample_fixture.yaml")
        assert config.policy == PolicyConfig()


class TestCustomDangerousPairs:
    def test_custom_pair_triggers_r003(self):
        config = make_fixture(
            policy={"dangerous_pairs": [["CapA", "CapB"]]}
        )
        graph = build_from_fixture(config)
        findings = run_all_rules(graph, config.analysis, config.policy)
        r003 = [f for f in findings if f.rule_id == "R003"]
        assert len(r003) == 1
        assert r003[0].entities["capability_a"] == "CapA"
        assert r003[0].entities["capability_b"] == "CapB"

    def test_default_pairs_do_not_trigger_on_custom_caps(self):
        config = make_fixture()
        graph = build_from_fixture(config)
        findings = run_all_rules(graph, config.analysis, config.policy)
        assert [f for f in findings if f.rule_id == "R003"] == []

    def test_empty_pairs_disable_r003(self):
        config = make_fixture(
            tools=[
                {"id": "tool_a", "capabilities": ["SecretRead"]},
                {"id": "tool_b", "capabilities": ["ExternalNetworkSend"]},
            ],
            capabilities=[
                {"id": "SecretRead", "severity": 4},
                {"id": "ExternalNetworkSend", "severity": 3},
            ],
            policy={"dangerous_pairs": []},
        )
        graph = build_from_fixture(config)
        findings = run_all_rules(graph, config.analysis, config.policy)
        assert [f for f in findings if f.rule_id == "R003"] == []


class TestCustomThresholds:
    def test_raised_critical_severity_drops_severity3_findings(self):
        config = make_fixture(
            capabilities=[
                {"id": "CapA", "severity": 3},
                {"id": "CapB", "severity": 2},
            ],
        )
        graph = build_from_fixture(config)
        default_findings = run_all_rules(graph, config.analysis)
        assert any(f.rule_id == "R001" for f in default_findings)

        strict = PolicyConfig(critical_severity=4)
        findings = run_all_rules(graph, config.analysis, strict)
        assert [f for f in findings if f.rule_id == "R001"] == []

    def test_lowered_critical_severity_adds_findings(self):
        config = make_fixture()  # severities are 2
        graph = build_from_fixture(config)
        assert run_all_rules(graph, config.analysis) == []

        loose = PolicyConfig(critical_severity=2)
        findings = run_all_rules(graph, config.analysis, loose)
        rule_ids = {f.rule_id for f in findings}
        assert "R001" in rule_ids
        assert "R005" in rule_ids

    def test_low_trust_max_zero_excludes_trust1_sources(self):
        config = make_fixture(
            context_sources=[
                {"id": "web", "source_type": "user_input", "trust_level": 1}
            ],
            capabilities=[
                {"id": "CapA", "severity": 4},
                {"id": "CapB", "severity": 2},
            ],
        )
        graph = build_from_fixture(config)
        assert any(
            f.rule_id == "R001" for f in run_all_rules(graph, config.analysis)
        )

        strict = PolicyConfig(low_trust_max=0)
        findings = run_all_rules(graph, config.analysis, strict)
        assert [f for f in findings if f.rule_id in ("R001", "R005")] == []

    def test_sensitive_sensitivity_threshold(self):
        config = make_fixture(
            capabilities=[
                {"id": "CapA", "severity": 4},
                {"id": "CapB", "severity": 2},
            ],
            resources=[{"id": "db", "type": "database", "sensitivity": 2}],
            capability_bindings=[{"capability": "CapA", "resource": "db"}],
        )
        graph = build_from_fixture(config)
        assert [
            f for f in run_all_rules(graph, config.analysis) if f.rule_id == "R002"
        ] == []

        loose = PolicyConfig(sensitive_sensitivity=2)
        findings = run_all_rules(graph, config.analysis, loose)
        r002 = [f for f in findings if f.rule_id == "R002"]
        assert len(r002) == 1
        assert r002[0].entities["resource"] == "db"


class TestTrustDefaults:
    @pytest.mark.parametrize(
        ("source_type", "expected"),
        [
            ("webpage", 0),
            ("external_api", 0),
            ("retrieval", 1),
            ("user_input", 1),
            ("memory", 2),
        ],
    )
    def test_trust_defaults_by_source_type(self, source_type, expected):
        cs = ContextSourceConfig(id="cs", source_type=source_type)
        assert cs.trust_level == expected

    def test_explicit_trust_level_wins(self):
        cs = ContextSourceConfig(id="cs", source_type="webpage", trust_level=3)
        assert cs.trust_level == 3

    def test_invalid_source_type_still_errors(self):
        with pytest.raises(Exception):
            ContextSourceConfig(id="cs", source_type="carrier_pigeon")

    def test_yaml_fixture_with_policy_and_trust_defaults(self, tmp_path):
        fixture = {
            "policy": {
                "critical_severity": 2,
                "dangerous_pairs": [["CapA", "CapB"]],
            },
            "context_sources": [{"id": "web", "source_type": "webpage"}],
            "agents": [
                {
                    "id": "agent",
                    "trust_level": 2,
                    "consumes": ["web"],
                    "can_invoke": ["tool_a"],
                }
            ],
            "tools": [{"id": "tool_a", "capabilities": ["CapA"]}],
            "capabilities": [{"id": "CapA", "severity": 2}],
        }
        path = tmp_path / "fixture.yaml"
        path.write_text(yaml.safe_dump(fixture), encoding="utf-8")
        config = load_fixture(path)
        assert config.context_sources[0].trust_level == 0
        assert config.policy.critical_severity == 2
        graph = build_from_fixture(config)
        findings = run_all_rules(graph, config.analysis, config.policy)
        assert any(f.rule_id == "R001" for f in findings)

    def test_analysis_config_unaffected(self):
        config = AnalysisConfig()
        assert config.overexposure_agent_threshold == 3
