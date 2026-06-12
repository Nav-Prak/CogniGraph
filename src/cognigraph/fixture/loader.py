from pathlib import Path

import yaml

from cognigraph.fixture.heuristics import apply_heuristic_capability_mapping
from cognigraph.fixture.models import FixtureConfig, ToolAnnotationsConfig


class FixtureValidationError(Exception):
    pass


def _load_yaml(path: Path) -> dict:
    with open(path, encoding="utf-8") as f:
        raw = yaml.safe_load(f)
    if raw is None:
        return {}
    if not isinstance(raw, dict):
        raise FixtureValidationError(f"Expected YAML mapping in '{path}'")
    return raw


def load_tool_annotations(path: Path) -> ToolAnnotationsConfig:
    return ToolAnnotationsConfig(**_load_yaml(path))


def load_fixture(
    path: Path,
    annotations_path: Path | None = None,
    infer_capabilities: bool = False,
) -> FixtureConfig:
    raw = _load_yaml(path)
    config = FixtureConfig(**raw)
    validate_references(config)
    if annotations_path is not None:
        annotations = load_tool_annotations(annotations_path)
        config = apply_tool_annotations(config, annotations)
    if infer_capabilities:
        config = apply_heuristic_capability_mapping(config)
        validate_references(config)
    return config


def apply_tool_annotations(
    config: FixtureConfig,
    annotations: ToolAnnotationsConfig,
) -> FixtureConfig:
    if not annotations.tool_capability_annotations:
        return config

    tool_ids = {tool.id for tool in config.tools}
    unknown_tools = sorted(
        tool_id
        for tool_id in annotations.tool_capability_annotations
        if tool_id not in tool_ids
    )
    if unknown_tools:
        raise FixtureValidationError(
            "Tool capability annotations reference unknown tool(s): "
            + ", ".join(unknown_tools)
        )

    updated_tools = []
    for tool in config.tools:
        annotation = annotations.tool_capability_annotations.get(tool.id)
        if annotation is None:
            updated_tools.append(tool)
            continue
        merged_capabilities = list(
            dict.fromkeys([*tool.capabilities, *annotation.capabilities])
        )
        updated_tools.append(
            tool.model_copy(update={"capabilities": merged_capabilities})
        )

    updated_config = config.model_copy(update={"tools": updated_tools})
    validate_references(updated_config)
    return updated_config


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
    for p in config.policies:
        id_to_types.setdefault(p.id, []).append("policy")
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

    agent_ids = {a.id for a in config.agents}
    policy_target_ids = agent_ids | tool_ids | mcp_server_ids
    for policy in config.policies:
        for target_id in policy.applies_to:
            if target_id not in policy_target_ids:
                errors.append(
                    f"Policy '{policy.id}' applies to unknown agent, tool, "
                    f"or MCP server '{target_id}'"
                )

    bound_capability_ids = {
        binding.capability
        for binding in config.capability_bindings
        if binding.capability in capability_ids
    }
    for capability in config.capabilities:
        if capability.resource_binding_required and capability.id not in bound_capability_ids:
            errors.append(
                f"Capability '{capability.id}' requires a resource binding"
            )

    if errors:
        raise FixtureValidationError(
            f"Fixture validation failed with {len(errors)} error(s):\n"
            + "\n".join(f"  - {e}" for e in errors)
        )
