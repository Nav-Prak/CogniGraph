from pathlib import Path

from cognigraph.fixture.loader import load_fixture
from cognigraph.graph.builder import build_from_fixture
from cognigraph.rules.engine import run_all_rules

FIXTURES_DIR = Path(__file__).resolve().parent.parent / "fixtures"


def test_phase0_acceptance():
    config = load_fixture(FIXTURES_DIR / "sample_fixture.yaml")
    graph = build_from_fixture(config)
    findings = run_all_rules(graph, config.analysis)

    by_rule = {}
    for f in findings:
        by_rule.setdefault(f.rule_id, []).append(f)

    # R001: low-trust context reaches critical capability
    r001 = by_rule["R001"]
    assert len(r001) == 4
    r001_caps = {f.entities["capability"] for f in r001}
    assert "SecretRead" in r001_caps
    for f in r001:
        assert f.entities["context_source"] == "external_webpage"
        assert f.entities["agent"] == "planner_agent"

    # R002: low-trust context reaches sensitive resource
    r002 = by_rule["R002"]
    assert len(r002) == 2
    r002_resources = {f.entities["resource"] for f in r002}
    assert "ssh_private_key" in r002_resources
    assert "github_repository" in r002_resources

    # R003: dangerous capability composition
    r003 = by_rule["R003"]
    assert len(r003) == 1
    assert r003[0].entities["capability_a"] == "SecretRead"
    assert r003[0].entities["capability_b"] == "ExternalNetworkSend"
    assert r003[0].entities["agent"] == "planner_agent"

    # R004: overprivileged MCP exposure — not triggered (only 1 agent)
    assert "R004" not in by_rule

    # R005: trust boundary crossing
    r005 = by_rule["R005"]
    assert len(r005) == 4
    for f in r005:
        assert f.entities["context_source"] == "external_webpage"
        assert f.entities["agent"] == "planner_agent"
    r005_caps = {f.entities["capability"] for f in r005}
    assert "SecretRead" in r005_caps
