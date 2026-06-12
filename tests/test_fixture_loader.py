import pytest
from pydantic import ValidationError

from cognigraph.fixture.heuristics import (
    apply_heuristic_capability_mapping,
    infer_capabilities_for_tool,
)
from cognigraph.fixture.loader import (
    FixtureValidationError,
    apply_tool_annotations,
    load_fixture,
    load_tool_annotations,
    validate_references,
)
from cognigraph.fixture.models import (
    AgentConfig,
    AnalysisConfig,
    CapabilityBinding,
    CapabilityConfig,
    ContextSourceConfig,
    FixtureConfig,
    MCPServerConfig,
    ResourceConfig,
    ToolAnnotationsConfig,
    ToolCapabilityAnnotation,
    ToolConfig,
)
from cognigraph.schemas.enums import ResourceType, SourceType

from pathlib import Path

FIXTURES_DIR = Path(__file__).resolve().parent.parent / "fixtures"


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


class TestLoadFixture:
    def test_load_sample(self):
        config = load_fixture(FIXTURES_DIR / "sample_fixture.yaml")
        assert len(config.agents) == 1
        assert len(config.tools) == 2
        assert len(config.capabilities) == 4
        assert len(config.resources) == 2
        assert len(config.capability_bindings) == 2
        assert config.analysis.max_tool_invocation_depth == 5

    def test_load_with_annotations(self, tmp_path):
        fixture = tmp_path / "fixture.yaml"
        fixture.write_text(
            """
tools:
  - id: fs_tool

capabilities:
  - id: SecretRead
    severity: 4
""",
            encoding="utf-8",
        )
        annotations = tmp_path / "annotations.yaml"
        annotations.write_text(
            """
tool_capability_annotations:
  fs_tool:
    capabilities:
      - SecretRead
""",
            encoding="utf-8",
        )

        config = load_fixture(fixture, annotations_path=annotations)
        assert config.tools[0].capabilities == ["SecretRead"]

    def test_load_with_heuristic_capability_mapping(self, tmp_path):
        fixture = tmp_path / "fixture.yaml"
        fixture.write_text(
            """
tools:
  - id: fs_tool
    description: Read files and secrets from disk.

capabilities:
  - id: SecretRead
    severity: 4
  - id: FilesystemRead
    severity: 3
""",
            encoding="utf-8",
        )

        config = load_fixture(fixture, infer_capabilities=True)
        assert config.tools[0].capabilities == ["SecretRead", "FilesystemRead"]

    def test_load_annotations_bad_yaml_shape(self, tmp_path):
        annotations = tmp_path / "annotations.yaml"
        annotations.write_text("- not-a-mapping\n", encoding="utf-8")
        with pytest.raises(FixtureValidationError, match="Expected YAML mapping"):
            load_tool_annotations(annotations)


class TestToolAnnotations:
    def test_apply_tool_annotations_merges_and_dedupes(self):
        config = FixtureConfig(
            tools=[
                ToolConfig(
                    id="fs_tool",
                    capabilities=["FilesystemRead"],
                )
            ],
            capabilities=[
                CapabilityConfig(id="FilesystemRead", severity=3),
                CapabilityConfig(id="SecretRead", severity=4),
            ],
        )
        annotations = ToolAnnotationsConfig(
            tool_capability_annotations={
                "fs_tool": ToolCapabilityAnnotation(
                    capabilities=["FilesystemRead", "SecretRead"]
                )
            }
        )

        updated = apply_tool_annotations(config, annotations)
        assert updated.tools[0].capabilities == ["FilesystemRead", "SecretRead"]

    def test_apply_tool_annotations_rejects_unknown_tool(self):
        config = FixtureConfig(tools=[ToolConfig(id="fs_tool")])
        annotations = ToolAnnotationsConfig(
            tool_capability_annotations={
                "ghost_tool": ToolCapabilityAnnotation(capabilities=["SecretRead"])
            }
        )
        with pytest.raises(FixtureValidationError, match="unknown tool"):
            apply_tool_annotations(config, annotations)

    def test_apply_tool_annotations_rejects_unknown_capability(self):
        config = FixtureConfig(tools=[ToolConfig(id="fs_tool")])
        annotations = ToolAnnotationsConfig(
            tool_capability_annotations={
                "fs_tool": ToolCapabilityAnnotation(capabilities=["SecretRead"])
            }
        )
        with pytest.raises(FixtureValidationError, match="unknown capability"):
            apply_tool_annotations(config, annotations)


class TestHeuristicCapabilityMapping:
    def test_infers_from_tool_description(self):
        tool = ToolConfig(
            id="fs_tool",
            description="Read files and secrets from disk.",
        )
        inferred = infer_capabilities_for_tool(
            tool,
            {"SecretRead", "FilesystemRead", "ShellExecution"},
        )
        assert inferred == ["SecretRead", "FilesystemRead"]

    def test_does_not_infer_undeclared_capabilities(self):
        tool = ToolConfig(
            id="shell_runner",
            description="Execute command in a shell.",
        )
        inferred = infer_capabilities_for_tool(tool, {"SecretRead"})
        assert inferred == []

    def test_apply_heuristics_merges_with_existing_capabilities(self):
        config = FixtureConfig(
            tools=[
                ToolConfig(
                    id="github_tool",
                    description="Push commits to GitHub.",
                    capabilities=["ExternalNetworkSend"],
                )
            ],
            capabilities=[
                CapabilityConfig(id="ExternalNetworkSend", severity=3),
                CapabilityConfig(id="GitHubPush", severity=4),
            ],
        )
        updated = apply_heuristic_capability_mapping(config)
        assert updated.tools[0].capabilities == [
            "ExternalNetworkSend",
            "GitHubPush",
        ]


class TestValidateReferences:
    def test_valid_config_passes(self):
        config = load_fixture(FIXTURES_DIR / "sample_fixture.yaml")
        validate_references(config)

    def test_bad_agent_consumes(self):
        config = FixtureConfig(
            agents=[AgentConfig(id="a", trust_level=1, consumes=["nonexistent"])],
        )
        with pytest.raises(FixtureValidationError, match="unknown context source"):
            validate_references(config)

    def test_bad_agent_invokes(self):
        config = FixtureConfig(
            agents=[AgentConfig(id="a", trust_level=1, can_invoke=["ghost_tool"])],
        )
        with pytest.raises(FixtureValidationError, match="unknown tool"):
            validate_references(config)

    def test_bad_tool_mcp_server(self):
        config = FixtureConfig(
            tools=[ToolConfig(id="t", mcp_server="ghost_server")],
        )
        with pytest.raises(FixtureValidationError, match="unknown MCP server"):
            validate_references(config)

    def test_bad_tool_capability(self):
        config = FixtureConfig(
            tools=[ToolConfig(id="t", capabilities=["FakeCapability"])],
        )
        with pytest.raises(FixtureValidationError, match="unknown capability"):
            validate_references(config)

    def test_bad_binding_capability(self):
        config = FixtureConfig(
            capability_bindings=[CapabilityBinding(capability="Fake", resource="r")],
            resources=[ResourceConfig(id="r", type=ResourceType.SECRET, sensitivity=3)],
        )
        with pytest.raises(FixtureValidationError, match="unknown capability"):
            validate_references(config)

    def test_bad_binding_resource(self):
        config = FixtureConfig(
            capability_bindings=[CapabilityBinding(capability="c", resource="Fake")],
            capabilities=[CapabilityConfig(id="c", severity=3)],
        )
        with pytest.raises(FixtureValidationError, match="unknown resource"):
            validate_references(config)

    def test_multiple_errors_collected(self):
        config = FixtureConfig(
            agents=[
                AgentConfig(
                    id="a", trust_level=1,
                    consumes=["ghost1"], can_invoke=["ghost2"],
                ),
            ],
        )
        with pytest.raises(FixtureValidationError, match="2 error"):
            validate_references(config)

    def test_duplicate_id_across_types(self):
        config = FixtureConfig(
            agents=[AgentConfig(id="shared_id", trust_level=1)],
            tools=[ToolConfig(id="shared_id")],
        )
        with pytest.raises(FixtureValidationError, match="Duplicate ID"):
            validate_references(config)

    def test_duplicate_id_three_types(self):
        config = FixtureConfig(
            context_sources=[ContextSourceConfig(id="x", source_type=SourceType.WEBPAGE, trust_level=0)],
            agents=[AgentConfig(id="x", trust_level=1)],
            capabilities=[CapabilityConfig(id="x", severity=3)],
        )
        with pytest.raises(FixtureValidationError, match="Duplicate ID"):
            validate_references(config)

    def test_required_capability_binding_missing(self):
        config = FixtureConfig(
            capabilities=[
                CapabilityConfig(
                    id="SecretRead",
                    severity=4,
                    resource_binding_required=True,
                )
            ],
        )
        with pytest.raises(FixtureValidationError, match="requires a resource binding"):
            validate_references(config)

    def test_required_capability_binding_present(self):
        config = FixtureConfig(
            capabilities=[
                CapabilityConfig(
                    id="SecretRead",
                    severity=4,
                    resource_binding_required=True,
                )
            ],
            resources=[
                ResourceConfig(id="ssh_key", type=ResourceType.SECRET, sensitivity=4)
            ],
            capability_bindings=[
                CapabilityBinding(capability="SecretRead", resource="ssh_key")
            ],
        )
        validate_references(config)
