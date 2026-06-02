from __future__ import annotations

from cognigraph.fixture.models import FixtureConfig, ToolConfig

HEURISTIC_CAPABILITY_PATTERNS: dict[str, tuple[str, ...]] = {
    "SecretRead": (
        "secret",
        "credential",
        "api key",
        "token",
        "private key",
        "environment variable",
    ),
    "FilesystemRead": (
        "read file",
        "read files",
        "list file",
        "list directory",
        "filesystem read",
    ),
    "FilesystemWrite": (
        "write file",
        "edit file",
        "delete file",
        "filesystem write",
    ),
    "ShellExecution": (
        "execute command",
        "run command",
        "shell",
        "terminal",
    ),
    "ExternalNetworkSend": (
        "http request",
        "network request",
        "external api",
        "webhook",
        "send data",
    ),
    "EmailSend": (
        "send email",
        "mail",
    ),
    "GitHubRead": (
        "github read",
        "read repository",
        "list pull request",
    ),
    "GitHubPush": (
        "github push",
        "push commit",
        "create pull request",
        "write repository",
    ),
    "BrowserAutomation": (
        "browser",
        "web automation",
    ),
    "DatabaseWrite": (
        "database write",
        "insert row",
        "update database",
        "sql write",
    ),
    "CredentialAccess": (
        "password",
        "credential access",
    ),
}


def infer_capabilities_for_tool(
    tool: ToolConfig,
    available_capability_ids: set[str],
) -> list[str]:
    text = f"{tool.id} {tool.description or ''}".replace("_", " ").lower()
    inferred = []
    for capability_id, patterns in HEURISTIC_CAPABILITY_PATTERNS.items():
        if capability_id not in available_capability_ids:
            continue
        if any(pattern in text for pattern in patterns):
            inferred.append(capability_id)
    return inferred


def apply_heuristic_capability_mapping(config: FixtureConfig) -> FixtureConfig:
    available_capability_ids = {capability.id for capability in config.capabilities}
    updated_tools = []
    changed = False

    for tool in config.tools:
        inferred = infer_capabilities_for_tool(tool, available_capability_ids)
        merged_capabilities = list(dict.fromkeys([*tool.capabilities, *inferred]))
        if merged_capabilities != tool.capabilities:
            changed = True
            updated_tools.append(tool.model_copy(update={"capabilities": merged_capabilities}))
        else:
            updated_tools.append(tool)

    if not changed:
        return config
    return config.model_copy(update={"tools": updated_tools})
