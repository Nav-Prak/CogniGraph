import pytest
from pydantic import ValidationError

from cognigraph.fixture.models import (
    AgentConfig,
    AnalysisConfig,
    CapabilityBinding,
    CapabilityConfig,
    ContextSourceConfig,
    FixtureConfig,
    MCPServerConfig,
    ResourceConfig,
    ToolConfig,
)
from cognigraph.schemas.enums import ResourceType, SourceType


class TestAnalysisConfig:
    def test_defaults(self):
        cfg = AnalysisConfig()
        assert cfg.max_tool_invocation_depth == 5
        assert cfg.max_path_length == 8
        assert cfg.overexposure_agent_threshold == 3

    def test_custom_values(self):
        cfg = AnalysisConfig(
            max_tool_invocation_depth=10,
            max_path_length=15,
            overexposure_agent_threshold=5,
        )
        assert cfg.max_tool_invocation_depth == 10

    def test_depth_must_be_positive(self):
        with pytest.raises(ValidationError):
            AnalysisConfig(max_tool_invocation_depth=0)


class TestContextSourceConfig:
    def test_valid(self):
        cs = ContextSourceConfig(
            id="web", source_type=SourceType.WEBPAGE, trust_level=0
        )
        assert cs.id == "web"

    def test_invalid_trust(self):
        with pytest.raises(ValidationError):
            ContextSourceConfig(
                id="x", source_type=SourceType.WEBPAGE, trust_level=5
            )


class TestAgentConfig:
    def test_valid(self):
        a = AgentConfig(
            id="planner",
            trust_level=2,
            consumes=["web"],
            can_invoke=["tool1"],
        )
        assert a.consumes == ["web"]
        assert a.can_invoke == ["tool1"]

    def test_defaults(self):
        a = AgentConfig(id="minimal", trust_level=1)
        assert a.consumes == []
        assert a.can_invoke == []


class TestToolConfig:
    def test_valid(self):
        t = ToolConfig(
            id="fs_tool",
            mcp_server="fs_mcp",
            can_invoke=[],
            capabilities=["SecretRead"],
        )
        assert t.capabilities == ["SecretRead"]

    def test_defaults(self):
        t = ToolConfig(id="standalone")
        assert t.mcp_server is None
        assert t.can_invoke == []
        assert t.capabilities == []


class TestCapabilityConfig:
    def test_valid(self):
        c = CapabilityConfig(id="SecretRead", severity=4, resource_binding_required=True)
        assert c.severity == 4

    def test_severity_bounds(self):
        with pytest.raises(ValidationError):
            CapabilityConfig(id="x", severity=0)
        with pytest.raises(ValidationError):
            CapabilityConfig(id="x", severity=5)


class TestResourceConfig:
    def test_valid(self):
        r = ResourceConfig(id="ssh_key", type=ResourceType.SECRET, sensitivity=4)
        assert r.sensitivity == 4

    def test_sensitivity_bounds(self):
        with pytest.raises(ValidationError):
            ResourceConfig(id="x", type=ResourceType.DATABASE, sensitivity=0)


class TestCapabilityBinding:
    def test_valid(self):
        b = CapabilityBinding(capability="SecretRead", resource="ssh_key")
        assert b.capability == "SecretRead"
        assert b.resource == "ssh_key"


class TestFixtureConfig:
    def test_empty(self):
        cfg = FixtureConfig()
        assert cfg.context_sources == []
        assert cfg.agents == []
        assert cfg.tools == []
        assert cfg.analysis.max_tool_invocation_depth == 5

    def test_full_fixture(self):
        cfg = FixtureConfig(
            analysis=AnalysisConfig(max_tool_invocation_depth=5, max_path_length=8),
            context_sources=[
                ContextSourceConfig(
                    id="external_webpage",
                    source_type=SourceType.WEBPAGE,
                    trust_level=0,
                ),
            ],
            agents=[
                AgentConfig(
                    id="planner_agent",
                    trust_level=2,
                    consumes=["external_webpage"],
                    can_invoke=["filesystem_tool", "github_tool"],
                ),
            ],
            tools=[
                ToolConfig(
                    id="filesystem_tool",
                    mcp_server="filesystem_mcp",
                    capabilities=["SecretRead", "FilesystemRead"],
                ),
                ToolConfig(
                    id="github_tool",
                    mcp_server="github_mcp",
                    capabilities=["GitHubPush", "ExternalNetworkSend"],
                ),
            ],
            mcp_servers=[
                MCPServerConfig(id="filesystem_mcp"),
                MCPServerConfig(id="github_mcp"),
            ],
            capabilities=[
                CapabilityConfig(id="SecretRead", severity=4, resource_binding_required=True),
                CapabilityConfig(id="FilesystemRead", severity=3),
                CapabilityConfig(id="GitHubPush", severity=4, resource_binding_required=True),
                CapabilityConfig(id="ExternalNetworkSend", severity=3),
            ],
            resources=[
                ResourceConfig(id="ssh_private_key", type=ResourceType.SECRET, sensitivity=4),
                ResourceConfig(id="github_repository", type=ResourceType.REPOSITORY, sensitivity=3),
            ],
            capability_bindings=[
                CapabilityBinding(capability="SecretRead", resource="ssh_private_key"),
                CapabilityBinding(capability="GitHubPush", resource="github_repository"),
            ],
        )
        assert len(cfg.agents) == 1
        assert len(cfg.tools) == 2
        assert len(cfg.capabilities) == 4
        assert len(cfg.capability_bindings) == 2
