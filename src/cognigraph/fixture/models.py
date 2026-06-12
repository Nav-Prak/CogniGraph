from pydantic import BaseModel, Field, model_validator

from cognigraph.schemas.enums import PolicyEffect, ResourceType, SourceType

DEFAULT_DANGEROUS_PAIRS: tuple[tuple[str, str], ...] = (
    ("SecretRead", "ExternalNetworkSend"),
    ("FilesystemRead", "EmailSend"),
    ("ShellExecution", "ExternalNetworkSend"),
    ("GitHubRead", "GitHubPush"),
    ("BrowserAutomation", "CredentialAccess"),
)

# Defaults applied when a context source omits trust_level.
SOURCE_TYPE_TRUST_DEFAULTS: dict[SourceType, int] = {
    SourceType.WEBPAGE: 0,
    SourceType.EXTERNAL_API: 0,
    SourceType.RETRIEVAL: 1,
    SourceType.USER_INPUT: 1,
    SourceType.MEMORY: 2,
}


class AnalysisConfig(BaseModel, frozen=True):
    max_tool_invocation_depth: int = Field(default=5, ge=1)
    max_path_length: int = Field(default=8, ge=1)
    overexposure_agent_threshold: int = Field(default=3, ge=1)


class PolicyConfig(BaseModel, frozen=True):
    critical_severity: int = Field(default=3, ge=1, le=4)
    sensitive_sensitivity: int = Field(default=3, ge=1, le=4)
    low_trust_max: int = Field(default=1, ge=0, le=4)
    dangerous_pairs: list[tuple[str, str]] = Field(
        default_factory=lambda: [tuple(pair) for pair in DEFAULT_DANGEROUS_PAIRS]
    )


class ContextSourceConfig(BaseModel, frozen=True):
    id: str
    source_type: SourceType
    trust_level: int = Field(ge=0, le=4)

    @model_validator(mode="before")
    @classmethod
    def _default_trust_from_source_type(cls, data):
        if isinstance(data, dict) and data.get("trust_level") is None:
            try:
                source_type = SourceType(data.get("source_type"))
            except ValueError:
                return data
            data = {
                **data,
                "trust_level": SOURCE_TYPE_TRUST_DEFAULTS[source_type],
            }
        return data


class AgentConfig(BaseModel, frozen=True):
    id: str
    trust_level: int = Field(ge=0, le=4)
    consumes: list[str] = Field(default_factory=list)
    can_invoke: list[str] = Field(default_factory=list)


class ToolConfig(BaseModel, frozen=True):
    id: str
    description: str | None = None
    mcp_server: str | None = None
    can_invoke: list[str] = Field(default_factory=list)
    capabilities: list[str] = Field(default_factory=list)


class ToolCapabilityAnnotation(BaseModel, frozen=True):
    capabilities: list[str] = Field(default_factory=list)


class ToolAnnotationsConfig(BaseModel, frozen=True):
    tool_capability_annotations: dict[str, ToolCapabilityAnnotation] = Field(
        default_factory=dict
    )


class MCPServerConfig(BaseModel, frozen=True):
    id: str


class CapabilityConfig(BaseModel, frozen=True):
    id: str
    severity: int = Field(ge=1, le=4)
    resource_binding_required: bool = False


class ResourceConfig(BaseModel, frozen=True):
    id: str
    type: ResourceType
    sensitivity: int = Field(ge=1, le=4)


class CapabilityBinding(BaseModel, frozen=True):
    capability: str
    resource: str


class PolicyNodeConfig(BaseModel, frozen=True):
    """An approval/control boundary applied to agents, tools, or MCP servers.

    Findings whose path crosses a protected node are mitigated (treated like
    an accepted risk, default) or downgraded one severity level, depending on
    `effect`.
    """

    id: str
    applies_to: list[str] = Field(min_length=1)
    effect: PolicyEffect = PolicyEffect.MITIGATE
    description: str | None = None


class FixtureConfig(BaseModel, frozen=True):
    analysis: AnalysisConfig = Field(default_factory=AnalysisConfig)
    policy: PolicyConfig = Field(default_factory=PolicyConfig)
    context_sources: list[ContextSourceConfig] = Field(default_factory=list)
    agents: list[AgentConfig] = Field(default_factory=list)
    tools: list[ToolConfig] = Field(default_factory=list)
    mcp_servers: list[MCPServerConfig] = Field(default_factory=list)
    capabilities: list[CapabilityConfig] = Field(default_factory=list)
    resources: list[ResourceConfig] = Field(default_factory=list)
    capability_bindings: list[CapabilityBinding] = Field(default_factory=list)
    policies: list[PolicyNodeConfig] = Field(default_factory=list)
