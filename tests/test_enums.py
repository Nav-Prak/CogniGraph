import pytest

from cognigraph.schemas.enums import (
    EdgeType,
    NodeType,
    ResourceType,
    SourceType,
    TrustLevel,
)


class TestTrustLevel:
    def test_values(self):
        assert TrustLevel.UNTRUSTED == 0
        assert TrustLevel.LOW == 1
        assert TrustLevel.MEDIUM == 2
        assert TrustLevel.HIGH == 3
        assert TrustLevel.PRIVILEGED == 4

    def test_ordering(self):
        assert TrustLevel.UNTRUSTED < TrustLevel.LOW
        assert TrustLevel.LOW < TrustLevel.MEDIUM
        assert TrustLevel.MEDIUM < TrustLevel.HIGH
        assert TrustLevel.HIGH < TrustLevel.PRIVILEGED

    def test_numeric_comparison(self):
        assert TrustLevel.LOW <= 1
        assert TrustLevel.HIGH >= 3


class TestSourceType:
    def test_all_values(self):
        expected = {"user_input", "retrieval", "memory", "external_api", "webpage"}
        assert {s.value for s in SourceType} == expected

    def test_string_value(self):
        assert SourceType.WEBPAGE == "webpage"


class TestResourceType:
    def test_all_values(self):
        expected = {
            "secret", "filesystem_path", "database", "repository",
            "browser_session", "email_account", "environment_variables",
        }
        assert {r.value for r in ResourceType} == expected


class TestEdgeType:
    def test_all_values(self):
        expected = {
            "CONSUMED_BY", "CAN_INVOKE", "EXPOSES_CAPABILITY",
            "CAN_ACCESS_RESOURCE", "RUNS_IN", "USES_SERVER",
        }
        assert {e.value for e in EdgeType} == expected


class TestNodeType:
    def test_all_values(self):
        expected = {
            "Agent", "Tool", "MCPServer", "ContextSource",
            "Capability", "Resource", "ExecutionEnvironment",
        }
        assert {n.value for n in NodeType} == expected

    def test_count(self):
        assert len(NodeType) == 7
