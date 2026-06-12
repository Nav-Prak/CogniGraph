from cognigraph.fixture.models import (
    DEFAULT_DANGEROUS_PAIRS,
    AnalysisConfig,
    PolicyConfig,
)
from cognigraph.graph.builder import CogniGraph
from cognigraph.schemas.enums import EdgeType, NodeType
from cognigraph.schemas.findings import Finding, FindingSeverity

# Kept for backwards compatibility; the canonical default lives in
# fixture/models.py and per-fixture overrides come from the policy block.
DANGEROUS_PAIRS: list[tuple[str, str]] = [
    tuple(pair) for pair in DEFAULT_DANGEROUS_PAIRS
]

RECOMMENDED_CONTROLS: dict[str, str] = {
    "R001": (
        "Restrict low-trust context from reaching this capability, remove the "
        "agent-to-tool invocation edge if unnecessary, or require approval "
        "before the capability can be used."
    ),
    "R002": (
        "Narrow or remove the capability binding to the sensitive resource, "
        "reduce the resource sensitivity exposure, or place an approval "
        "boundary before access."
    ),
    "R003": (
        "Split the dangerous capability pair across separate agents, tools, "
        "MCP servers, or approval boundaries so one agent cannot compose both "
        "actions."
    ),
    "R004": (
        "Reduce the number of agents that can invoke this MCP-backed "
        "capability, split critical tools onto a dedicated server, or lower "
        "server exposure."
    ),
    "R005": (
        "Add a trust boundary between low-trust input and the higher-trust "
        "agent, sanitize or restrict the context source, or remove downstream "
        "critical capability access."
    ),
}


def _reachable_capabilities_with_paths(
    graph: CogniGraph, agent_id: str, max_depth: int
) -> dict[str, list[str]]:
    tool_paths = graph.get_reachable_with_paths(agent_id, max_depth)
    cap_to_path: dict[str, list[str]] = {}
    for tool_id, tool_path in tool_paths.items():
        for cap_id in graph.get_capabilities_of_tool(tool_id):
            if cap_id not in cap_to_path:
                cap_to_path[cap_id] = tool_path + [cap_id]
    return cap_to_path


def _within_path_length(path: list[str], config: AnalysisConfig) -> bool:
    return len(path) <= config.max_path_length


def low_trust_to_critical_capability(
    graph: CogniGraph,
    config: AnalysisConfig,
    policy: PolicyConfig | None = None,
) -> list[Finding]:
    policy = policy or PolicyConfig()
    findings: list[Finding] = []
    for cs_id in graph.get_nodes_by_type(NodeType.CONTEXT_SOURCE):
        cs = graph.get_node(cs_id)
        if cs["trust_level"] > policy.low_trust_max:
            continue
        for agent_id in graph.get_successors(cs_id, EdgeType.CONSUMED_BY):
            cap_paths = _reachable_capabilities_with_paths(
                graph, agent_id, config.max_tool_invocation_depth
            )
            for cap_id, tool_path in cap_paths.items():
                cap = graph.get_node(cap_id)
                if cap["severity"] >= policy.critical_severity:
                    path = [cs_id] + tool_path
                    if not _within_path_length(path, config):
                        continue
                    findings.append(Finding(
                        rule_id="R001",
                        title="Low-trust context reaches critical capability",
                        description=(
                            f"Low-trust context '{cs_id}' can reach "
                            f"capability '{cap_id}' (severity {cap['severity']})"
                        ),
                        severity=FindingSeverity.CRITICAL
                        if cap["severity"] > policy.critical_severity
                        else FindingSeverity.HIGH,
                        path=path,
                        entities={
                            "context_source": cs_id,
                            "agent": agent_id,
                            "capability": cap_id,
                        },
                        recommended_control=RECOMMENDED_CONTROLS["R001"],
                    ))
    return findings


def low_trust_to_sensitive_resource(
    graph: CogniGraph,
    config: AnalysisConfig,
    policy: PolicyConfig | None = None,
) -> list[Finding]:
    policy = policy or PolicyConfig()
    findings: list[Finding] = []
    for cs_id in graph.get_nodes_by_type(NodeType.CONTEXT_SOURCE):
        cs = graph.get_node(cs_id)
        if cs["trust_level"] > policy.low_trust_max:
            continue
        for agent_id in graph.get_successors(cs_id, EdgeType.CONSUMED_BY):
            cap_paths = _reachable_capabilities_with_paths(
                graph, agent_id, config.max_tool_invocation_depth
            )
            for cap_id, tool_path in cap_paths.items():
                for res_id in graph.get_resources_of_capability(cap_id):
                    res = graph.get_node(res_id)
                    if res["sensitivity"] >= policy.sensitive_sensitivity:
                        path = [cs_id] + tool_path + [res_id]
                        if not _within_path_length(path, config):
                            continue
                        findings.append(Finding(
                            rule_id="R002",
                            title="Low-trust context reaches sensitive resource",
                            description=(
                                f"Low-trust context '{cs_id}' can reach "
                                f"resource '{res_id}' (sensitivity {res['sensitivity']}) "
                                f"via capability '{cap_id}'"
                            ),
                            severity=FindingSeverity.CRITICAL
                            if res["sensitivity"] > policy.sensitive_sensitivity
                            else FindingSeverity.HIGH,
                            path=path,
                            entities={
                                "context_source": cs_id,
                                "agent": agent_id,
                                "capability": cap_id,
                                "resource": res_id,
                            },
                            recommended_control=RECOMMENDED_CONTROLS["R002"],
                        ))
    return findings


def dangerous_capability_composition(
    graph: CogniGraph,
    config: AnalysisConfig,
    policy: PolicyConfig | None = None,
) -> list[Finding]:
    policy = policy or PolicyConfig()
    findings: list[Finding] = []
    for agent_id in graph.get_nodes_by_type(NodeType.AGENT):
        cap_paths = _reachable_capabilities_with_paths(
            graph, agent_id, config.max_tool_invocation_depth
        )
        cap_ids = set(cap_paths.keys())
        for cap_a, cap_b in policy.dangerous_pairs:
            if cap_a in cap_ids and cap_b in cap_ids:
                path = [agent_id, cap_a, cap_b]
                if not _within_path_length(path, config):
                    continue
                findings.append(Finding(
                    rule_id="R003",
                    title="Dangerous capability composition",
                    description=(
                        f"Agent '{agent_id}' can reach both "
                        f"'{cap_a}' and '{cap_b}'"
                    ),
                    severity=FindingSeverity.HIGH,
                    path=path,
                    entities={
                        "agent": agent_id,
                        "capability_a": cap_a,
                        "capability_b": cap_b,
                    },
                    recommended_control=RECOMMENDED_CONTROLS["R003"],
                ))
    return findings


def overprivileged_mcp_exposure(
    graph: CogniGraph,
    config: AnalysisConfig,
    policy: PolicyConfig | None = None,
) -> list[Finding]:
    policy = policy or PolicyConfig()
    findings: list[Finding] = []
    for server_id in graph.get_nodes_by_type(NodeType.MCP_SERVER):
        tools_on_server = graph.get_predecessors(server_id, EdgeType.USES_SERVER)
        critical_tools: list[str] = []
        for tool_id in tools_on_server:
            for cap_id in graph.get_capabilities_of_tool(tool_id):
                cap = graph.get_node(cap_id)
                if cap["severity"] >= policy.critical_severity:
                    critical_tools.append(tool_id)
                    break

        if not critical_tools:
            continue

        invoking_agents: set[str] = set()
        for tool_id in critical_tools:
            invoking_agents.update(
                graph.get_agents_reaching_tool(
                    tool_id, config.max_tool_invocation_depth
                )
            )

        if len(invoking_agents) >= config.overexposure_agent_threshold:
            findings.append(Finding(
                rule_id="R004",
                title="Overprivileged MCP exposure",
                description=(
                    f"MCP server '{server_id}' backs critical tools "
                    f"invokable by {len(invoking_agents)} agents "
                    f"(threshold: {config.overexposure_agent_threshold})"
                ),
                severity=FindingSeverity.HIGH,
                path=[server_id] + sorted(invoking_agents),
                entities={
                    "mcp_server": server_id,
                    "agent_count": str(len(invoking_agents)),
                },
                recommended_control=RECOMMENDED_CONTROLS["R004"],
            ))
    return findings


def trust_boundary_crossing(
    graph: CogniGraph,
    config: AnalysisConfig,
    policy: PolicyConfig | None = None,
) -> list[Finding]:
    policy = policy or PolicyConfig()
    findings: list[Finding] = []
    for agent_id in graph.get_nodes_by_type(NodeType.AGENT):
        agent = graph.get_node(agent_id)
        if agent["trust_level"] <= policy.low_trust_max:
            continue

        low_trust_sources: list[str] = []
        for cs_id in graph.get_predecessors(agent_id, EdgeType.CONSUMED_BY):
            cs = graph.get_node(cs_id)
            if cs["trust_level"] <= policy.low_trust_max:
                low_trust_sources.append(cs_id)

        if not low_trust_sources:
            continue

        cap_paths = _reachable_capabilities_with_paths(
            graph, agent_id, config.max_tool_invocation_depth
        )
        for cap_id, tool_path in cap_paths.items():
            cap = graph.get_node(cap_id)
            if cap["severity"] >= policy.critical_severity:
                for cs_id in low_trust_sources:
                    path = [cs_id] + tool_path
                    if not _within_path_length(path, config):
                        continue
                    findings.append(Finding(
                        rule_id="R005",
                        title="Trust boundary crossing",
                        description=(
                            f"Low-trust context '{cs_id}' enters "
                            f"higher-trust agent '{agent_id}' "
                            f"(trust_level {agent['trust_level']}) "
                            f"with critical downstream capability '{cap_id}'"
                        ),
                        severity=FindingSeverity.CRITICAL,
                        path=path,
                        entities={
                            "context_source": cs_id,
                            "agent": agent_id,
                            "capability": cap_id,
                        },
                        recommended_control=RECOMMENDED_CONTROLS["R005"],
                    ))
    return findings


ALL_RULES = [
    low_trust_to_critical_capability,
    low_trust_to_sensitive_resource,
    dangerous_capability_composition,
    overprivileged_mcp_exposure,
    trust_boundary_crossing,
]


def run_all_rules(
    graph: CogniGraph,
    config: AnalysisConfig,
    policy: PolicyConfig | None = None,
) -> list[Finding]:
    findings: list[Finding] = []
    for rule in ALL_RULES:
        findings.extend(rule(graph, config, policy))
    findings.sort(key=lambda f: (f.rule_id, f.path))
    return findings
