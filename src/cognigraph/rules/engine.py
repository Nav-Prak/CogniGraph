from cognigraph.fixture.models import AnalysisConfig
from cognigraph.graph.builder import CogniGraph
from cognigraph.schemas.enums import EdgeType, NodeType
from cognigraph.schemas.findings import Finding, FindingSeverity

DANGEROUS_PAIRS: list[tuple[str, str]] = [
    ("SecretRead", "ExternalNetworkSend"),
    ("FilesystemRead", "EmailSend"),
    ("ShellExecution", "ExternalNetworkSend"),
    ("GitHubRead", "GitHubPush"),
    ("BrowserAutomation", "CredentialAccess"),
]


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


def low_trust_to_critical_capability(
    graph: CogniGraph, config: AnalysisConfig
) -> list[Finding]:
    findings: list[Finding] = []
    for cs_id in graph.get_nodes_by_type(NodeType.CONTEXT_SOURCE):
        cs = graph.get_node(cs_id)
        if cs["trust_level"] > 1:
            continue
        for agent_id in graph.get_successors(cs_id, EdgeType.CONSUMED_BY):
            cap_paths = _reachable_capabilities_with_paths(
                graph, agent_id, config.max_tool_invocation_depth
            )
            for cap_id, tool_path in cap_paths.items():
                cap = graph.get_node(cap_id)
                if cap["severity"] >= 3:
                    path = [cs_id] + tool_path
                    findings.append(Finding(
                        rule_id="R001",
                        title="Low-trust context reaches critical capability",
                        description=(
                            f"Low-trust context '{cs_id}' can reach "
                            f"capability '{cap_id}' (severity {cap['severity']})"
                        ),
                        severity=FindingSeverity.CRITICAL
                        if cap["severity"] >= 4 else FindingSeverity.HIGH,
                        path=path,
                        entities={
                            "context_source": cs_id,
                            "agent": agent_id,
                            "capability": cap_id,
                        },
                    ))
    return findings


def low_trust_to_sensitive_resource(
    graph: CogniGraph, config: AnalysisConfig
) -> list[Finding]:
    findings: list[Finding] = []
    for cs_id in graph.get_nodes_by_type(NodeType.CONTEXT_SOURCE):
        cs = graph.get_node(cs_id)
        if cs["trust_level"] > 1:
            continue
        for agent_id in graph.get_successors(cs_id, EdgeType.CONSUMED_BY):
            cap_paths = _reachable_capabilities_with_paths(
                graph, agent_id, config.max_tool_invocation_depth
            )
            for cap_id, tool_path in cap_paths.items():
                for res_id in graph.get_resources_of_capability(cap_id):
                    res = graph.get_node(res_id)
                    if res["sensitivity"] >= 3:
                        path = [cs_id] + tool_path + [res_id]
                        findings.append(Finding(
                            rule_id="R002",
                            title="Low-trust context reaches sensitive resource",
                            description=(
                                f"Low-trust context '{cs_id}' can reach "
                                f"resource '{res_id}' (sensitivity {res['sensitivity']}) "
                                f"via capability '{cap_id}'"
                            ),
                            severity=FindingSeverity.CRITICAL
                            if res["sensitivity"] >= 4 else FindingSeverity.HIGH,
                            path=path,
                            entities={
                                "context_source": cs_id,
                                "agent": agent_id,
                                "capability": cap_id,
                                "resource": res_id,
                            },
                        ))
    return findings


def dangerous_capability_composition(
    graph: CogniGraph, config: AnalysisConfig
) -> list[Finding]:
    findings: list[Finding] = []
    for agent_id in graph.get_nodes_by_type(NodeType.AGENT):
        cap_paths = _reachable_capabilities_with_paths(
            graph, agent_id, config.max_tool_invocation_depth
        )
        cap_ids = set(cap_paths.keys())
        for cap_a, cap_b in DANGEROUS_PAIRS:
            if cap_a in cap_ids and cap_b in cap_ids:
                findings.append(Finding(
                    rule_id="R003",
                    title="Dangerous capability composition",
                    description=(
                        f"Agent '{agent_id}' can reach both "
                        f"'{cap_a}' and '{cap_b}'"
                    ),
                    severity=FindingSeverity.HIGH,
                    path=[agent_id, cap_a, cap_b],
                    entities={
                        "agent": agent_id,
                        "capability_a": cap_a,
                        "capability_b": cap_b,
                    },
                ))
    return findings


def overprivileged_mcp_exposure(
    graph: CogniGraph, config: AnalysisConfig
) -> list[Finding]:
    findings: list[Finding] = []
    for server_id in graph.get_nodes_by_type(NodeType.MCP_SERVER):
        tools_on_server = graph.get_predecessors(server_id, EdgeType.USES_SERVER)
        critical_tools: list[str] = []
        for tool_id in tools_on_server:
            for cap_id in graph.get_capabilities_of_tool(tool_id):
                cap = graph.get_node(cap_id)
                if cap["severity"] >= 3:
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
            ))
    return findings


def trust_boundary_crossing(
    graph: CogniGraph, config: AnalysisConfig
) -> list[Finding]:
    findings: list[Finding] = []
    for agent_id in graph.get_nodes_by_type(NodeType.AGENT):
        agent = graph.get_node(agent_id)
        if agent["trust_level"] < 2:
            continue

        low_trust_sources: list[str] = []
        for cs_id in graph.get_predecessors(agent_id, EdgeType.CONSUMED_BY):
            cs = graph.get_node(cs_id)
            if cs["trust_level"] <= 1:
                low_trust_sources.append(cs_id)

        if not low_trust_sources:
            continue

        cap_paths = _reachable_capabilities_with_paths(
            graph, agent_id, config.max_tool_invocation_depth
        )
        for cap_id, tool_path in cap_paths.items():
            cap = graph.get_node(cap_id)
            if cap["severity"] >= 3:
                for cs_id in low_trust_sources:
                    path = [cs_id] + tool_path
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
    graph: CogniGraph, config: AnalysisConfig
) -> list[Finding]:
    findings: list[Finding] = []
    for rule in ALL_RULES:
        findings.extend(rule(graph, config))
    findings.sort(key=lambda f: (f.rule_id, f.path))
    return findings
