import pytest

from cognigraph.fixture.models import AnalysisConfig, FixtureConfig
from cognigraph.graph.builder import CogniGraph
from cognigraph.rules.engine import (
    dangerous_capability_composition,
    low_trust_to_critical_capability,
    low_trust_to_sensitive_resource,
    overprivileged_mcp_exposure,
    run_all_rules,
    trust_boundary_crossing,
)


class TestLowTrustToCriticalCapability:
    def test_finds_all_critical_paths(self, sample_graph: CogniGraph, sample_config: FixtureConfig):
        findings = low_trust_to_critical_capability(sample_graph, sample_config.analysis)
        assert len(findings) == 4
        cap_ids = {f.entities["capability"] for f in findings}
        assert cap_ids == {"SecretRead", "FilesystemRead", "GitHubPush", "ExternalNetworkSend"}

    def test_all_reference_context_source(self, sample_graph: CogniGraph, sample_config: FixtureConfig):
        findings = low_trust_to_critical_capability(sample_graph, sample_config.analysis)
        for f in findings:
            assert f.entities["context_source"] == "external_webpage"
            assert f.rule_id == "R001"

    def test_full_path(self, sample_graph: CogniGraph, sample_config: FixtureConfig):
        findings = low_trust_to_critical_capability(sample_graph, sample_config.analysis)
        for f in findings:
            assert f.path[0] == "external_webpage"
            assert f.path[1] == "planner_agent"
            assert f.path[-1] == f.entities["capability"]
            assert len(f.path) >= 4


class TestLowTrustToSensitiveResource:
    def test_finds_resource_paths(self, sample_graph: CogniGraph, sample_config: FixtureConfig):
        findings = low_trust_to_sensitive_resource(sample_graph, sample_config.analysis)
        assert len(findings) == 2
        res_ids = {f.entities["resource"] for f in findings}
        assert res_ids == {"ssh_private_key", "github_repository"}

    def test_full_path(self, sample_graph: CogniGraph, sample_config: FixtureConfig):
        findings = low_trust_to_sensitive_resource(sample_graph, sample_config.analysis)
        for f in findings:
            assert f.path[0] == "external_webpage"
            assert f.path[1] == "planner_agent"
            assert f.path[-1] == f.entities["resource"]
            assert f.path[-2] == f.entities["capability"]
            assert len(f.path) >= 5
            assert f.rule_id == "R002"


class TestDangerousCapabilityComposition:
    def test_finds_secret_read_plus_network_send(self, sample_graph: CogniGraph, sample_config: FixtureConfig):
        findings = dangerous_capability_composition(sample_graph, sample_config.analysis)
        assert len(findings) == 1
        f = findings[0]
        assert f.entities["capability_a"] == "SecretRead"
        assert f.entities["capability_b"] == "ExternalNetworkSend"
        assert f.entities["agent"] == "planner_agent"
        assert f.rule_id == "R003"


class TestOverprivilegedMCPExposure:
    def test_no_findings_below_threshold(self, sample_graph: CogniGraph, sample_config: FixtureConfig):
        findings = overprivileged_mcp_exposure(sample_graph, sample_config.analysis)
        assert len(findings) == 0

    def test_triggers_at_threshold(self, sample_graph: CogniGraph):
        config = AnalysisConfig(overexposure_agent_threshold=1)
        findings = overprivileged_mcp_exposure(sample_graph, config)
        assert len(findings) == 2


class TestTrustBoundaryCrossing:
    def test_finds_boundary_crossings(self, sample_graph: CogniGraph, sample_config: FixtureConfig):
        findings = trust_boundary_crossing(sample_graph, sample_config.analysis)
        assert len(findings) == 4
        for f in findings:
            assert f.entities["context_source"] == "external_webpage"
            assert f.entities["agent"] == "planner_agent"
            assert f.rule_id == "R005"

    def test_all_caps_are_critical(self, sample_graph: CogniGraph, sample_config: FixtureConfig):
        findings = trust_boundary_crossing(sample_graph, sample_config.analysis)
        cap_ids = {f.entities["capability"] for f in findings}
        assert cap_ids == {"SecretRead", "FilesystemRead", "GitHubPush", "ExternalNetworkSend"}

    def test_full_path(self, sample_graph: CogniGraph, sample_config: FixtureConfig):
        findings = trust_boundary_crossing(sample_graph, sample_config.analysis)
        for f in findings:
            assert f.path[0] == "external_webpage"
            assert f.path[1] == "planner_agent"
            assert f.path[-1] == f.entities["capability"]
            assert len(f.path) >= 4


class TestRunAllRules:
    def test_returns_sorted_findings(self, sample_graph: CogniGraph, sample_config: FixtureConfig):
        findings = run_all_rules(sample_graph, sample_config.analysis)
        rule_ids = [f.rule_id for f in findings]
        assert rule_ids == sorted(rule_ids)

    def test_total_finding_count(self, sample_graph: CogniGraph, sample_config: FixtureConfig):
        findings = run_all_rules(sample_graph, sample_config.analysis)
        # R001: 4, R002: 2, R003: 1, R004: 0, R005: 4 = 11
        assert len(findings) == 11
