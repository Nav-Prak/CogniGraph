import pytest
from pydantic import ValidationError

from cognigraph.schemas.enums import NodeType, ResourceType, SourceType
from cognigraph.schemas.nodes import (
    Agent,
    Capability,
    ContextSource,
    ExecutionEnvironment,
    MCPServer,
    Resource,
    Tool,
)


class TestContextSource:
    def test_valid(self):
        cs = ContextSource(id="web", source_type=SourceType.WEBPAGE, trust_level=0)
        assert cs.id == "web"
        assert cs.source_type == SourceType.WEBPAGE
        assert cs.trust_level == 0
        assert cs.node_type == NodeType.CONTEXT_SOURCE

    def test_trust_level_bounds(self):
        ContextSource(id="a", source_type=SourceType.MEMORY, trust_level=0)
        ContextSource(id="b", source_type=SourceType.MEMORY, trust_level=4)

    def test_trust_level_too_high(self):
        with pytest.raises(ValidationError):
            ContextSource(id="x", source_type=SourceType.WEBPAGE, trust_level=5)

    def test_trust_level_negative(self):
        with pytest.raises(ValidationError):
            ContextSource(id="x", source_type=SourceType.WEBPAGE, trust_level=-1)

    def test_invalid_source_type(self):
        with pytest.raises(ValidationError):
            ContextSource(id="x", source_type="invalid", trust_level=0)

    def test_frozen(self):
        cs = ContextSource(id="web", source_type=SourceType.WEBPAGE, trust_level=0)
        with pytest.raises(ValidationError):
            cs.trust_level = 3


class TestAgent:
    def test_valid(self):
        a = Agent(id="planner", trust_level=2)
        assert a.id == "planner"
        assert a.trust_level == 2
        assert a.node_type == NodeType.AGENT

    def test_trust_level_too_high(self):
        with pytest.raises(ValidationError):
            Agent(id="x", trust_level=5)

    def test_trust_level_negative(self):
        with pytest.raises(ValidationError):
            Agent(id="x", trust_level=-1)

    def test_frozen(self):
        a = Agent(id="planner", trust_level=2)
        with pytest.raises(ValidationError):
            a.id = "other"


class TestTool:
    def test_valid_with_server(self):
        t = Tool(id="fs_tool", mcp_server="fs_mcp")
        assert t.id == "fs_tool"
        assert t.mcp_server == "fs_mcp"
        assert t.node_type == NodeType.TOOL

    def test_valid_without_server(self):
        t = Tool(id="standalone")
        assert t.mcp_server is None

    def test_frozen(self):
        t = Tool(id="fs_tool")
        with pytest.raises(ValidationError):
            t.id = "other"


class TestMCPServer:
    def test_valid(self):
        s = MCPServer(id="fs_mcp")
        assert s.id == "fs_mcp"
        assert s.node_type == NodeType.MCP_SERVER


class TestCapability:
    def test_valid(self):
        c = Capability(id="SecretRead", severity=4, resource_binding_required=True)
        assert c.id == "SecretRead"
        assert c.severity == 4
        assert c.resource_binding_required is True
        assert c.node_type == NodeType.CAPABILITY

    def test_default_binding(self):
        c = Capability(id="ShellExec", severity=3)
        assert c.resource_binding_required is False

    def test_severity_too_high(self):
        with pytest.raises(ValidationError):
            Capability(id="x", severity=5)

    def test_severity_too_low(self):
        with pytest.raises(ValidationError):
            Capability(id="x", severity=0)

    def test_frozen(self):
        c = Capability(id="SecretRead", severity=4)
        with pytest.raises(ValidationError):
            c.severity = 1


class TestResource:
    def test_valid(self):
        r = Resource(id="ssh_key", type=ResourceType.SECRET, sensitivity=4)
        assert r.id == "ssh_key"
        assert r.type == ResourceType.SECRET
        assert r.sensitivity == 4
        assert r.node_type == NodeType.RESOURCE

    def test_sensitivity_too_high(self):
        with pytest.raises(ValidationError):
            Resource(id="x", type=ResourceType.DATABASE, sensitivity=5)

    def test_sensitivity_too_low(self):
        with pytest.raises(ValidationError):
            Resource(id="x", type=ResourceType.DATABASE, sensitivity=0)

    def test_invalid_type(self):
        with pytest.raises(ValidationError):
            Resource(id="x", type="invalid", sensitivity=3)

    def test_frozen(self):
        r = Resource(id="ssh_key", type=ResourceType.SECRET, sensitivity=4)
        with pytest.raises(ValidationError):
            r.sensitivity = 1


class TestExecutionEnvironment:
    def test_valid(self):
        e = ExecutionEnvironment(id="sandbox")
        assert e.id == "sandbox"
        assert e.node_type == NodeType.EXECUTION_ENVIRONMENT

    def test_frozen(self):
        e = ExecutionEnvironment(id="sandbox")
        with pytest.raises(ValidationError):
            e.id = "other"
