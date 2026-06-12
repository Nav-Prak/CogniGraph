from pathlib import Path

import pytest
import yaml

from cognigraph.cli import main
from cognigraph.fixture.loader import FixtureValidationError, load_fixture
from cognigraph.fixture.models import FixtureConfig
from cognigraph.graph.builder import build_from_fixture
from cognigraph.rules.engine import run_all_rules
from cognigraph.rules.grouping import (
    active_groups,
    group_findings,
    mitigated_groups,
)
from cognigraph.rules.mitigation import apply_policy_mitigations
from cognigraph.schemas.enums import EdgeType, NodeType
from cognigraph.schemas.findings import FindingSeverity

FIXTURES_DIR = Path(__file__).resolve().parent.parent / "fixtures"


def base_fixture(policies=None) -> dict:
    """The canonical threat scenario: webpage -> planner -> secret read."""
    data = {
        "context_sources": [
            {"id": "external_webpage", "source_type": "webpage"}
        ],
        "agents": [
            {
                "id": "planner_agent",
                "trust_level": 2,
                "consumes": ["external_webpage"],
                "can_invoke": ["filesystem_tool"],
            }
        ],
        "tools": [
            {
                "id": "filesystem_tool",
                "mcp_server": "filesystem_mcp",
                "capabilities": ["SecretRead"],
            }
        ],
        "mcp_servers": [{"id": "filesystem_mcp"}],
        "capabilities": [{"id": "SecretRead", "severity": 4}],
    }
    if policies is not None:
        data["policies"] = policies
    return data


def run_findings(data: dict):
    config = FixtureConfig(**data)
    graph = build_from_fixture(config)
    findings = run_all_rules(graph, config.analysis, config.policy)
    return config, apply_policy_mitigations(graph, config, findings)


class TestPolicyMitigation:
    def test_unprotected_fixture_has_active_findings(self):
        _, findings = run_findings(base_fixture())
        assert findings
        assert all(f.mitigated_by is None for f in findings)
        assert active_groups(group_findings(findings))

    def test_policy_on_tool_mitigates_findings(self):
        _, findings = run_findings(
            base_fixture(
                policies=[
                    {"id": "fs_approval", "applies_to": ["filesystem_tool"]}
                ]
            )
        )
        assert findings
        assert all(f.mitigated_by == "fs_approval" for f in findings)
        groups = group_findings(findings)
        assert active_groups(groups) == []
        assert len(mitigated_groups(groups)) == len(groups)

    def test_removing_policy_restores_findings(self):
        protected = base_fixture(
            policies=[{"id": "fs_approval", "applies_to": ["filesystem_tool"]}]
        )
        unprotected = base_fixture()
        _, protected_findings = run_findings(protected)
        _, unprotected_findings = run_findings(unprotected)
        assert active_groups(group_findings(protected_findings)) == []
        assert active_groups(group_findings(unprotected_findings))
        stripped = [
            f.model_copy(update={"mitigated_by": None})
            for f in protected_findings
        ]
        assert stripped == unprotected_findings

    def test_policy_on_agent_mitigates(self):
        _, findings = run_findings(
            base_fixture(
                policies=[{"id": "agent_gate", "applies_to": ["planner_agent"]}]
            )
        )
        assert all(f.mitigated_by == "agent_gate" for f in findings)

    def test_policy_on_mcp_server_covers_backing_tools(self):
        _, findings = run_findings(
            base_fixture(
                policies=[{"id": "server_gate", "applies_to": ["filesystem_mcp"]}]
            )
        )
        assert findings
        assert all(f.mitigated_by == "server_gate" for f in findings)

    def test_downgrade_effect_keeps_findings_active(self):
        _, plain_findings = run_findings(base_fixture())
        _, findings = run_findings(
            base_fixture(
                policies=[
                    {
                        "id": "fs_review",
                        "applies_to": ["filesystem_tool"],
                        "effect": "downgrade",
                    }
                ]
            )
        )
        assert findings
        assert all(f.mitigated_by is None for f in findings)
        for plain, downgraded in zip(plain_findings, findings):
            assert downgraded.severity == FindingSeverity(plain.severity - 1)
        assert active_groups(group_findings(findings))

    def test_downgrade_floors_at_info(self):
        from cognigraph.rules.mitigation import _downgrade

        assert _downgrade(FindingSeverity.INFO) == FindingSeverity.INFO

    def test_partial_coverage_keeps_group_active(self):
        # Two tools expose the same capability; only one is protected. The
        # engine reports a single deduplicated path (which may run through
        # the protected tool), but mitigation must not claim the risk is
        # gated while the unprotected tool remains reachable.
        data = base_fixture(
            policies=[{"id": "fs_approval", "applies_to": ["filesystem_tool"]}]
        )
        data["tools"].append(
            {"id": "backup_tool", "capabilities": ["SecretRead"]}
        )
        data["agents"][0]["can_invoke"].append("backup_tool")
        _, findings = run_findings(data)
        groups = group_findings(findings)
        r001 = [g for g in groups if g.rule_id == "R001"]
        assert len(r001) == 1
        assert r001[0].mitigated_by is None
        assert r001[0] in active_groups(groups)

    def test_full_coverage_across_tools_mitigates(self):
        # Same alternate-tool topology, but both tools are protected.
        data = base_fixture(
            policies=[
                {
                    "id": "fs_approval",
                    "applies_to": ["filesystem_tool", "backup_tool"],
                }
            ]
        )
        data["tools"].append(
            {"id": "backup_tool", "capabilities": ["SecretRead"]}
        )
        data["agents"][0]["can_invoke"].append("backup_tool")
        _, findings = run_findings(data)
        groups = group_findings(findings)
        r001 = [g for g in groups if g.rule_id == "R001"]
        assert r001[0].mitigated_by == "fs_approval"
        assert r001[0] not in active_groups(groups)


class TestCompositionAndExposureGates:
    def composition_fixture(self, policies=None) -> dict:
        data = {
            "context_sources": [{"id": "web", "source_type": "webpage"}],
            "agents": [
                {
                    "id": "agent",
                    "trust_level": 1,
                    "consumes": ["web"],
                    "can_invoke": ["secret_tool", "net_tool"],
                }
            ],
            "tools": [
                {"id": "secret_tool", "capabilities": ["SecretRead"]},
                {"id": "net_tool", "capabilities": ["ExternalNetworkSend"]},
            ],
            "capabilities": [
                {"id": "SecretRead", "severity": 2},
                {"id": "ExternalNetworkSend", "severity": 2},
            ],
        }
        if policies is not None:
            data["policies"] = policies
        return data

    def test_r003_gated_by_protecting_one_side(self):
        _, findings = run_findings(
            self.composition_fixture(
                policies=[{"id": "secret_gate", "applies_to": ["secret_tool"]}]
            )
        )
        r003 = [f for f in findings if f.rule_id == "R003"]
        assert len(r003) == 1
        assert r003[0].mitigated_by == "secret_gate"

    def test_r003_active_without_policy(self):
        _, findings = run_findings(self.composition_fixture())
        r003 = [f for f in findings if f.rule_id == "R003"]
        assert len(r003) == 1
        assert r003[0].mitigated_by is None

    def exposure_fixture(self, policies=None) -> dict:
        agents = [
            {"id": f"agent_{i}", "trust_level": 2, "can_invoke": ["shared_tool"]}
            for i in range(3)
        ]
        data = {
            "agents": agents,
            "tools": [
                {
                    "id": "shared_tool",
                    "mcp_server": "shared_mcp",
                    "capabilities": ["ShellExecution"],
                }
            ],
            "mcp_servers": [{"id": "shared_mcp"}],
            "capabilities": [{"id": "ShellExecution", "severity": 4}],
        }
        if policies is not None:
            data["policies"] = policies
        return data

    def test_r004_gated_by_server_policy(self):
        _, findings = run_findings(
            self.exposure_fixture(
                policies=[{"id": "server_gate", "applies_to": ["shared_mcp"]}]
            )
        )
        r004 = [f for f in findings if f.rule_id == "R004"]
        assert len(r004) == 1
        assert r004[0].mitigated_by == "server_gate"

    def test_r004_gated_when_all_agents_protected(self):
        _, findings = run_findings(
            self.exposure_fixture(
                policies=[
                    {
                        "id": "agent_gate",
                        "applies_to": ["agent_0", "agent_1", "agent_2"],
                    }
                ]
            )
        )
        r004 = [f for f in findings if f.rule_id == "R004"]
        assert r004[0].mitigated_by == "agent_gate"

    def test_r004_active_when_some_agents_unprotected(self):
        _, findings = run_findings(
            self.exposure_fixture(
                policies=[{"id": "agent_gate", "applies_to": ["agent_0"]}]
            )
        )
        r004 = [f for f in findings if f.rule_id == "R004"]
        assert r004[0].mitigated_by is None


class TestPolicyValidationAndGraph:
    def test_unknown_applies_to_rejected(self):
        data = base_fixture(
            policies=[{"id": "p", "applies_to": ["no_such_node"]}]
        )
        with pytest.raises(FixtureValidationError, match="unknown agent, tool"):
            config = FixtureConfig(**data)
            from cognigraph.fixture.loader import validate_references

            validate_references(config)

    def test_empty_applies_to_rejected(self):
        with pytest.raises(Exception):
            FixtureConfig(
                **base_fixture(policies=[{"id": "p", "applies_to": []}])
            )

    def test_policy_node_and_edges_in_graph(self):
        config = FixtureConfig(
            **base_fixture(
                policies=[{"id": "fs_approval", "applies_to": ["filesystem_tool"]}]
            )
        )
        graph = build_from_fixture(config)
        assert graph.get_nodes_by_type(NodeType.POLICY) == ["fs_approval"]
        assert graph.get_successors("fs_approval", EdgeType.APPLIES_TO) == [
            "filesystem_tool"
        ]

    def test_yaml_round_trip(self, tmp_path):
        path = tmp_path / "f.yaml"
        path.write_text(
            yaml.safe_dump(
                base_fixture(
                    policies=[
                        {
                            "id": "fs_approval",
                            "applies_to": ["filesystem_tool"],
                            "description": "human approval before secret reads",
                        }
                    ]
                )
            ),
            encoding="utf-8",
        )
        config = load_fixture(path)
        assert config.policies[0].effect.value == "mitigate"


class TestPolicyCLI:
    def write_fixture(self, tmp_path, policies=None) -> str:
        path = tmp_path / "f.yaml"
        path.write_text(
            yaml.safe_dump(base_fixture(policies=policies)), encoding="utf-8"
        )
        return str(path)

    def test_mitigated_fixture_exits_zero(self, tmp_path, capsys):
        fixture = self.write_fixture(
            tmp_path,
            policies=[{"id": "fs_approval", "applies_to": ["filesystem_tool"]}],
        )
        rc = main([fixture])
        out = capsys.readouterr().out
        assert rc == 0
        assert "Mitigated by Policy" in out
        assert "fs_approval" in out

    def test_unprotected_fixture_exits_two(self, tmp_path):
        fixture = self.write_fixture(tmp_path)
        assert main([fixture, "--quiet"]) == 2

    def test_downgrade_fixture_still_fails_on_any(self, tmp_path):
        fixture = self.write_fixture(
            tmp_path,
            policies=[
                {
                    "id": "fs_review",
                    "applies_to": ["filesystem_tool"],
                    "effect": "downgrade",
                }
            ],
        )
        assert main([fixture, "--quiet"]) == 2
        assert main([fixture, "--quiet", "--fail-on", "critical"]) == 0
