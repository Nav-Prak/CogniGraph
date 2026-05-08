from pydantic import BaseModel, Field

from cognigraph.schemas.enums import NodeType, ResourceType, SourceType


class ContextSource(BaseModel, frozen=True):
    id: str
    source_type: SourceType
    trust_level: int = Field(ge=0, le=4)

    @property
    def node_type(self) -> NodeType:
        return NodeType.CONTEXT_SOURCE


class Agent(BaseModel, frozen=True):
    id: str
    trust_level: int = Field(ge=0, le=4)

    @property
    def node_type(self) -> NodeType:
        return NodeType.AGENT


class Tool(BaseModel, frozen=True):
    id: str
    mcp_server: str | None = None

    @property
    def node_type(self) -> NodeType:
        return NodeType.TOOL


class MCPServer(BaseModel, frozen=True):
    id: str

    @property
    def node_type(self) -> NodeType:
        return NodeType.MCP_SERVER


class Capability(BaseModel, frozen=True):
    id: str
    severity: int = Field(ge=1, le=4)
    resource_binding_required: bool = False

    @property
    def node_type(self) -> NodeType:
        return NodeType.CAPABILITY


class Resource(BaseModel, frozen=True):
    id: str
    type: ResourceType
    sensitivity: int = Field(ge=1, le=4)

    @property
    def node_type(self) -> NodeType:
        return NodeType.RESOURCE


class ExecutionEnvironment(BaseModel, frozen=True):
    id: str

    @property
    def node_type(self) -> NodeType:
        return NodeType.EXECUTION_ENVIRONMENT
