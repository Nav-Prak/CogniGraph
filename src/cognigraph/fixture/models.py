from pydantic import BaseModel, Field

from cognigraph.schemas.enums import ResourceType, SourceType


class AnalysisConfig(BaseModel, frozen=True):
    max_tool_invocation_depth: int = Field(default=5, ge=1)
    max_path_length: int = Field(default=8, ge=1)
    overexposure_agent_threshold: int = Field(default=3, ge=1)


class ContextSourceConfig(BaseModel, frozen=True):
    id: str
    source_type: SourceType
    trust_level: int = Field(ge=0, le=4)


class AgentConfig(BaseModel, frozen=True):
    id: str
    trust_level: int = Field(ge=0, le=4)
    consumes: list[str] = Field(default_factory=list)
    can_invoke: list[str] = Field(default_factory=list)


class ToolConfig(BaseModel, frozen=True):
    id: str
    mcp_server: str | None = None
    can_invoke: list[str] = Field(default_factory=list)
    capabilities: list[str] = Field(default_factory=list)


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


class FixtureConfig(BaseModel, frozen=True):
    analysis: AnalysisConfig = Field(default_factory=AnalysisConfig)
    context_sources: list[ContextSourceConfig] = Field(default_factory=list)
    agents: list[AgentConfig] = Field(default_factory=list)
    tools: list[ToolConfig] = Field(default_factory=list)
    mcp_servers: list[MCPServerConfig] = Field(default_factory=list)
    capabilities: list[CapabilityConfig] = Field(default_factory=list)
    resources: list[ResourceConfig] = Field(default_factory=list)
    capability_bindings: list[CapabilityBinding] = Field(default_factory=list)
