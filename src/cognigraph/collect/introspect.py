"""Live MCP server introspection (I2).

Connects to configured MCP servers and enumerates their real tools via
``tools/list``, giving the collector per-tool granularity instead of one
stub tool per server. Spawning stdio servers executes third-party code, so
this is only ever reached through an explicit ``--introspect`` flag and the
``mcp`` SDK ships as an optional extra (``cognigraph[introspect]``).
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from importlib import util as importlib_util
from typing import Any, Callable

from cognigraph.collect.mcp_config import (
    CollectError,
    IntrospectionUnavailableError,
)


@dataclass(frozen=True)
class IntrospectedTool:
    name: str
    description: str = ""


def ensure_introspection_available() -> None:
    if importlib_util.find_spec("mcp") is None:
        raise IntrospectionUnavailableError(
            "Live introspection requires the optional 'mcp' dependency. "
            "Install it with: pip install 'cognigraph[introspect]' "
            "(or: uv sync --extra introspect)"
        )


def _transport_kind(entry: dict[str, Any]) -> str:
    if entry.get("command"):
        return "stdio"
    if entry.get("url"):
        if str(entry.get("type") or "").lower() == "sse":
            return "sse"
        return "http"
    raise CollectError("server entry declares neither 'command' nor 'url'")


async def _list_tools(session: Any) -> list[IntrospectedTool]:
    tools: list[IntrospectedTool] = []
    cursor: str | None = None
    while True:
        result = await session.list_tools(cursor=cursor)
        tools.extend(
            IntrospectedTool(name=tool.name, description=tool.description or "")
            for tool in result.tools
        )
        cursor = result.nextCursor
        if not cursor:
            break
    return tools


async def _introspect_stdio(entry: dict[str, Any]) -> list[IntrospectedTool]:
    from mcp import ClientSession, StdioServerParameters
    from mcp.client.stdio import get_default_environment, stdio_client

    env = get_default_environment()
    env.update(
        {str(key): str(value) for key, value in (entry.get("env") or {}).items()}
    )
    params = StdioServerParameters(
        command=str(entry["command"]),
        args=[str(arg) for arg in entry.get("args") or []],
        env=env,
    )
    async with stdio_client(params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            return await _list_tools(session)


async def _introspect_remote(
    entry: dict[str, Any], kind: str
) -> list[IntrospectedTool]:  # pragma: no cover - requires a live remote server
    from mcp import ClientSession

    url = str(entry["url"])
    headers = entry.get("headers") or None
    if kind == "sse":
        from mcp.client.sse import sse_client

        async with sse_client(url, headers=headers) as (read, write):
            async with ClientSession(read, write) as session:
                await session.initialize()
                return await _list_tools(session)

    from mcp.client.streamable_http import streamablehttp_client

    async with streamablehttp_client(url, headers=headers) as (read, write, _):
        async with ClientSession(read, write) as session:
            await session.initialize()
            return await _list_tools(session)


def introspect_server(
    name: str, entry: dict[str, Any], *, timeout: float = 10.0
) -> list[IntrospectedTool]:
    """List the tools a configured MCP server actually exposes.

    Raises IntrospectionUnavailableError when the mcp SDK is not installed,
    and CollectError (wrapping the underlying failure) when the server
    cannot be reached or does not answer within `timeout` seconds.
    """
    ensure_introspection_available()
    kind = _transport_kind(entry)

    async def _run() -> list[IntrospectedTool]:
        if kind == "stdio":
            return await _introspect_stdio(entry)
        return await _introspect_remote(entry, kind)

    try:
        return asyncio.run(asyncio.wait_for(_run(), timeout=timeout))
    except TimeoutError as e:
        raise CollectError(
            f"server '{name}' did not answer tools/list within {timeout:g}s"
        ) from e
    except CollectError:
        raise
    except Exception as e:
        raise CollectError(f"could not introspect server '{name}': {e}") from e


def make_introspector(
    timeout: float,
) -> Callable[[str, dict[str, Any]], list[IntrospectedTool]]:
    def _introspect(name: str, entry: dict[str, Any]) -> list[IntrospectedTool]:
        return introspect_server(name, entry, timeout=timeout)

    return _introspect
