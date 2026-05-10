from pathlib import Path

import yaml

from cognigraph.fixture.models import FixtureConfig


class FixtureValidationError(Exception):
    pass


def load_fixture(path: Path) -> FixtureConfig:
    with open(path) as f:
        raw = yaml.safe_load(f)
    if raw is None:
        raw = {}
    config = FixtureConfig(**raw)
    validate_references(config)
    return config


def _collect_ids(config: FixtureConfig) -> dict[str, list[str]]:
    id_to_types: dict[str, list[str]] = {}
    for cs in config.context_sources:
        id_to_types.setdefault(cs.id, []).append("context_source")
    for a in config.agents:
        id_to_types.setdefault(a.id, []).append("agent")
    for t in config.tools:
        id_to_types.setdefault(t.id, []).append("tool")
    for s in config.mcp_servers:
        id_to_types.setdefault(s.id, []).append("mcp_server")
    for c in config.capabilities:
        id_to_types.setdefault(c.id, []).append("capability")
    for r in config.resources:
        id_to_types.setdefault(r.id, []).append("resource")
    return id_to_types


def validate_references(config: FixtureConfig) -> None:
    errors: list[str] = []

    id_to_types = _collect_ids(config)
    for node_id, types in id_to_types.items():
        if len(types) > 1:
            errors.append(
                f"Duplicate ID '{node_id}' used across node types: {', '.join(types)}"
            )

    context_source_ids = {cs.id for cs in config.context_sources}
    tool_ids = {t.id for t in config.tools}
    mcp_server_ids = {s.id for s in config.mcp_servers}
    capability_ids = {c.id for c in config.capabilities}
    resource_ids = {r.id for r in config.resources}

    for agent in config.agents:
        for cs_id in agent.consumes:
            if cs_id not in context_source_ids:
                errors.append(
                    f"Agent '{agent.id}' consumes unknown context source '{cs_id}'"
                )
        for tool_id in agent.can_invoke:
            if tool_id not in tool_ids:
                errors.append(
                    f"Agent '{agent.id}' invokes unknown tool '{tool_id}'"
                )

    for tool in config.tools:
        if tool.mcp_server and tool.mcp_server not in mcp_server_ids:
            errors.append(
                f"Tool '{tool.id}' references unknown MCP server '{tool.mcp_server}'"
            )
        for cap_id in tool.capabilities:
            if cap_id not in capability_ids:
                errors.append(
                    f"Tool '{tool.id}' references unknown capability '{cap_id}'"
                )
        for invoked_id in tool.can_invoke:
            if invoked_id not in tool_ids:
                errors.append(
                    f"Tool '{tool.id}' invokes unknown tool '{invoked_id}'"
                )

    for binding in config.capability_bindings:
        if binding.capability not in capability_ids:
            errors.append(
                f"Capability binding references unknown capability '{binding.capability}'"
            )
        if binding.resource not in resource_ids:
            errors.append(
                f"Capability binding references unknown resource '{binding.resource}'"
            )

    if errors:
        raise FixtureValidationError(
            f"Fixture validation failed with {len(errors)} error(s):\n"
            + "\n".join(f"  - {e}" for e in errors)
        )
