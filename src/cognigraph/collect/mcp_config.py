from __future__ import annotations

import json
import re
from pathlib import Path
from typing import TYPE_CHECKING, Any, Callable

import yaml

from cognigraph.fixture.loader import validate_references
from cognigraph.fixture.models import FixtureConfig, PolicyConfig

if TYPE_CHECKING:
    from cognigraph.collect.introspect import IntrospectedTool


class CollectError(Exception):
    pass


class IntrospectionUnavailableError(CollectError):
    """The optional 'mcp' dependency needed for --introspect is missing."""


# The capability ids the heuristic mapper knows, with severities from the
# design taxonomy. Seeded so annotation files and --infer-capabilities can
# reference them without hand-editing the skeleton first.
SEEDED_CAPABILITIES: list[dict[str, Any]] = [
    {"id": "SecretRead", "severity": 4},
    {"id": "FilesystemRead", "severity": 3},
    {"id": "FilesystemWrite", "severity": 4},
    {"id": "ShellExecution", "severity": 4},
    {"id": "ExternalNetworkSend", "severity": 3},
    {"id": "EmailSend", "severity": 3},
    {"id": "GitHubRead", "severity": 2},
    {"id": "GitHubPush", "severity": 4},
    {"id": "BrowserAutomation", "severity": 2},
    {"id": "DatabaseWrite", "severity": 4},
    {"id": "CredentialAccess", "severity": 4},
]

DEFAULT_AGENT_ID = "host_agent"
DEFAULT_AGENT_TRUST_LEVEL = 2
DEFAULT_CONTEXT_SOURCE_ID = "user_input"
DEFAULT_CONTEXT_SOURCE_TRUST_LEVEL = 1


def _strip_jsonc(text: str) -> str:
    """Remove // and /* */ comments and trailing commas, string-aware.

    VS Code mcp.json files are JSONC; Claude/Cursor configs are plain JSON,
    which passes through unchanged.
    """
    out: list[str] = []
    i = 0
    n = len(text)
    in_string = False
    while i < n:
        ch = text[i]
        if in_string:
            out.append(ch)
            if ch == "\\" and i + 1 < n:
                out.append(text[i + 1])
                i += 2
                continue
            if ch == '"':
                in_string = False
            i += 1
            continue
        if ch == '"':
            in_string = True
            out.append(ch)
            i += 1
            continue
        if ch == "/" and i + 1 < n and text[i + 1] == "/":
            while i < n and text[i] != "\n":
                i += 1
            continue
        if ch == "/" and i + 1 < n and text[i + 1] == "*":
            i += 2
            while i + 1 < n and not (text[i] == "*" and text[i + 1] == "/"):
                i += 1
            i += 2
            continue
        out.append(ch)
        i += 1
    # Trailing commas: a comma followed only by whitespace and a closer.
    return re.sub(r",(\s*[}\]])", r"\1", "".join(out))


def _load_config(path: Path) -> dict[str, Any]:
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as e:
        raise CollectError(f"Could not read config file: {e}") from e
    try:
        raw = json.loads(_strip_jsonc(text))
    except json.JSONDecodeError as e:
        raise CollectError(f"Invalid JSON in '{path}': {e}") from e
    if not isinstance(raw, dict):
        raise CollectError(f"Expected a JSON object in '{path}'")
    return raw


def _server_entries(raw: dict[str, Any], path: Path) -> dict[str, Any]:
    # Claude Desktop / Claude Code / Cursor / Windsurf use "mcpServers";
    # VS Code .vscode/mcp.json uses "servers".
    for key in ("mcpServers", "servers"):
        entries = raw.get(key)
        if isinstance(entries, dict):
            return entries
    raise CollectError(
        f"No 'mcpServers' or 'servers' object found in '{path}'. "
        "Supported inputs: claude_desktop_config.json, .mcp.json, "
        ".cursor/mcp.json, .vscode/mcp.json"
    )


def _sanitize_id(name: str) -> str:
    sanitized = re.sub(r"[^A-Za-z0-9_]", "_", name).strip("_")
    if not sanitized:
        sanitized = "server"
    if sanitized[0].isdigit():
        sanitized = f"s_{sanitized}"
    return sanitized


def _unique_id(base: str, used: set[str]) -> str:
    candidate = base
    suffix = 2
    while candidate in used:
        candidate = f"{base}_{suffix}"
        suffix += 1
    used.add(candidate)
    return candidate


def _describe_server(name: str, entry: dict[str, Any]) -> str:
    command = entry.get("command")
    if command:
        args = entry.get("args") or []
        arg_text = " ".join(str(a) for a in args)
        detail = f"{command} {arg_text}".strip()
        return f"MCP server '{name}' (stdio): {detail}"
    url = entry.get("url")
    if url:
        transport = entry.get("type", "remote")
        return f"MCP server '{name}' ({transport}): {url}"
    return f"MCP server '{name}'"


def collect_from_mcp_config(
    path: Path,
    *,
    agent_id: str = DEFAULT_AGENT_ID,
    agent_trust_level: int = DEFAULT_AGENT_TRUST_LEVEL,
    seed_capabilities: bool = True,
    introspector: Callable[[str, dict[str, Any]], list[IntrospectedTool]]
    | None = None,
    warn: Callable[[str], None] | None = None,
) -> FixtureConfig:
    """Build a fixture skeleton from an MCP client config file.

    Emits exactly what the config proves (servers) plus the scaffolding the
    annotation workflow needs: one stub tool per server, one host agent that
    can invoke every tool, and a user_input context source. Capability
    semantics are intentionally left to --annotations / --infer-capabilities.

    When an `introspector` is supplied (the --introspect flag), each server
    is asked for its real tools via tools/list and per-tool nodes replace
    the stub; a server that fails introspection degrades back to its stub
    with a warning, so one unreachable server never sinks the collection.
    """
    raw = _load_config(path)
    entries = _server_entries(raw, path)
    if not entries:
        raise CollectError(f"Config '{path}' declares no MCP servers")

    emit_warning = warn or (lambda message: None)
    used_server_ids: set[str] = set()
    used_tool_ids: set[str] = set()
    servers: list[dict[str, Any]] = []
    tools: list[dict[str, Any]] = []
    for name, entry in entries.items():
        if not isinstance(entry, dict):
            raise CollectError(
                f"Server entry '{name}' in '{path}' is not an object"
            )
        server_id = _unique_id(_sanitize_id(name), used_server_ids)
        servers.append({"id": server_id})

        introspected: list[IntrospectedTool] | None = None
        if introspector is not None:
            try:
                introspected = introspector(name, entry)
            except IntrospectionUnavailableError:
                raise
            except Exception as e:
                emit_warning(
                    f"Introspection failed for server '{name}' ({e}); "
                    "falling back to a stub tool"
                )

        if introspected is not None:
            if not introspected:
                emit_warning(f"Server '{name}' reported no tools")
            for info in introspected:
                tool_id = _unique_id(
                    f"{server_id}_{_sanitize_id(info.name)}", used_tool_ids
                )
                description = f"Tool '{info.name}' on MCP server '{name}'"
                if info.description:
                    description = f"{description}: {info.description}"
                tools.append(
                    {
                        "id": tool_id,
                        "description": description,
                        "mcp_server": server_id,
                        "capabilities": [],
                    }
                )
            continue

        tools.append(
            {
                "id": _unique_id(f"{server_id}_tool", used_tool_ids),
                "description": _describe_server(name, entry),
                "mcp_server": server_id,
                "capabilities": [],
            }
        )

    data: dict[str, Any] = {
        "context_sources": [
            {
                "id": DEFAULT_CONTEXT_SOURCE_ID,
                "source_type": "user_input",
                "trust_level": DEFAULT_CONTEXT_SOURCE_TRUST_LEVEL,
            }
        ],
        "agents": [
            {
                "id": agent_id,
                "trust_level": agent_trust_level,
                "consumes": [DEFAULT_CONTEXT_SOURCE_ID],
                "can_invoke": [tool["id"] for tool in tools],
            }
        ],
        "tools": tools,
        "mcp_servers": servers,
        "capabilities": list(SEEDED_CAPABILITIES) if seed_capabilities else [],
    }

    config = FixtureConfig(**data)
    validate_references(config)
    return config


def fixture_to_yaml(config: FixtureConfig) -> str:
    data = config.model_dump(exclude_none=True, mode="json")
    # A default policy block is pure noise in a skeleton — omit it.
    if data.get("policy") == PolicyConfig().model_dump(mode="json"):
        del data["policy"]
    # Drop empty collections so the skeleton stays readable.
    data = {key: value for key, value in data.items() if value}
    return yaml.safe_dump(data, sort_keys=False, default_flow_style=False)
