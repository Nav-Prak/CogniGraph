from enum import IntEnum, Enum


class TrustLevel(IntEnum):
    UNTRUSTED = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    PRIVILEGED = 4


class SourceType(str, Enum):
    USER_INPUT = "user_input"
    RETRIEVAL = "retrieval"
    MEMORY = "memory"
    EXTERNAL_API = "external_api"
    WEBPAGE = "webpage"


class ResourceType(str, Enum):
    SECRET = "secret"
    FILESYSTEM_PATH = "filesystem_path"
    DATABASE = "database"
    REPOSITORY = "repository"
    BROWSER_SESSION = "browser_session"
    EMAIL_ACCOUNT = "email_account"
    ENVIRONMENT_VARIABLES = "environment_variables"


class EdgeType(str, Enum):
    CONSUMED_BY = "CONSUMED_BY"
    CAN_INVOKE = "CAN_INVOKE"
    EXPOSES_CAPABILITY = "EXPOSES_CAPABILITY"
    CAN_ACCESS_RESOURCE = "CAN_ACCESS_RESOURCE"
    RUNS_IN = "RUNS_IN"
    USES_SERVER = "USES_SERVER"
    APPLIES_TO = "APPLIES_TO"


class RuntimeEdgeType(str, Enum):
    INVOKED = "INVOKED"
    READ_FROM = "READ_FROM"
    WROTE_TO = "WROTE_TO"
    PASSED_TO = "PASSED_TO"
    RETRIEVED_FROM = "RETRIEVED_FROM"
    EXECUTED_IN = "EXECUTED_IN"


class NodeType(str, Enum):
    AGENT = "Agent"
    TOOL = "Tool"
    MCP_SERVER = "MCPServer"
    CONTEXT_SOURCE = "ContextSource"
    CAPABILITY = "Capability"
    RESOURCE = "Resource"
    EXECUTION_ENVIRONMENT = "ExecutionEnvironment"
    POLICY = "Policy"


class PolicyEffect(str, Enum):
    MITIGATE = "mitigate"
    DOWNGRADE = "downgrade"
