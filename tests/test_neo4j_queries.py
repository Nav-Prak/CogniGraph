import pytest

from cognigraph.fixture.models import AnalysisConfig, FixtureConfig
from cognigraph.neo4j.client import Neo4jClient
from cognigraph.neo4j.queries import (
    dangerous_capability_composition,
    low_trust_to_critical_capability,
    low_trust_to_sensitive_resource,
    overprivileged_mcp_exposure,
    run_all_cypher_rules,
    trust_boundary_crossing,
)


pytestmark = pytest.mark.neo4j


class TestLowTrustToCriticalCapability:
    def test_finds_all_critical_paths(self, neo4j_client: Neo4jClient, sample_config: FixtureConfig):
        findings = low_trust_to_critical_capability(neo4j_client, sample_config.analysis)
        assert len(findings) == 4
        cap_ids = {f.entities["capability"] for f in findings}
        assert cap_ids == {"SecretRead", "FilesystemRead", "GitHubPush", "ExternalNetworkSend"}

    def test_all_reference_context_source(self, neo4j_client: Neo4jClient, sample_config: FixtureConfig):
        findings = low_trust_to_critical_capability(neo4j_client, sample_config.analysis)
        for f in findings:
            assert f.entities["context_source"] == "external_webpage"
            assert f.rule_id == "R001"


class TestLowTrustToSensitiveResource:
    def test_finds_resource_paths(self, neo4j_client: Neo4jClient, sample_config: FixtureConfig):
        findings = low_trust_to_sensitive_resource(neo4j_client, sample_config.analysis)
        assert len(findings) == 2
        res_ids = {f.entities["resource"] for f in findings}
        assert res_ids == {"ssh_private_key", "github_repository"}

    def test_path_includes_capability(self, neo4j_client: Neo4jClient, sample_config: FixtureConfig):
        findings = low_trust_to_sensitive_resource(neo4j_client, sample_config.analysis)
        for f in findings:
            assert len(f.path) == 5
            assert f.rule_id == "R002"


class TestDangerousCapabilityComposition:
    def test_finds_secret_read_plus_network_send(self, neo4j_client: Neo4jClient, sample_config: FixtureConfig):
        findings = dangerous_capability_composition(neo4j_client, sample_config.analysis)
        assert len(findings) == 1
        f = findings[0]
        assert f.entities["capability_a"] == "SecretRead"
        assert f.entities["capability_b"] == "ExternalNetworkSend"
        assert f.entities["agent"] == "planner_agent"
        assert f.rule_id == "R003"


class TestOverprivilegedMCPExposure:
    def test_no_findings_below_threshold(self, neo4j_client: Neo4jClient, sample_config: FixtureConfig):
        findings = overprivileged_mcp_exposure(neo4j_client, sample_config.analysis)
        assert len(findings) == 0

    def test_triggers_at_threshold(self, neo4j_client: Neo4jClient):
        config = AnalysisConfig(overexposure_agent_threshold=1)
        findings = overprivileged_mcp_exposure(neo4j_client, config)
        assert len(findings) == 2


class TestTrustBoundaryCrossing:
    def test_finds_boundary_crossings(self, neo4j_client: Neo4jClient, sample_config: FixtureConfig):
        findings = trust_boundary_crossing(neo4j_client, sample_config.analysis)
        assert len(findings) == 4
        for f in findings:
            assert f.entities["context_source"] == "external_webpage"
            assert f.entities["agent"] == "planner_agent"
            assert f.rule_id == "R005"


class TestRunAllCypherRules:
    def test_matches_in_memory_count(self, neo4j_client: Neo4jClient, sample_config: FixtureConfig):
        findings = run_all_cypher_rules(neo4j_client, sample_config.analysis)
        # Same as in-memory: R001:4 + R002:2 + R003:1 + R004:0 + R005:4 = 11
        assert len(findings) == 11

    def test_returns_sorted(self, neo4j_client: Neo4jClient, sample_config: FixtureConfig):
        findings = run_all_cypher_rules(neo4j_client, sample_config.analysis)
        rule_ids = [f.rule_id for f in findings]
        assert rule_ids == sorted(rule_ids)
