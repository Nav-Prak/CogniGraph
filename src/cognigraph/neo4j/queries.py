from __future__ import annotations

from cognigraph.fixture.models import AnalysisConfig, PolicyConfig
from cognigraph.neo4j.client import Neo4jClient
from cognigraph.rules.engine import RECOMMENDED_CONTROLS
from cognigraph.schemas.findings import Finding, FindingSeverity


def _path_node_ids(path) -> list[str]:
    return [node["id"] for node in path.nodes]


def _within_path_length(path: list[str], config: AnalysisConfig) -> bool:
    return len(path) <= config.max_path_length


def low_trust_to_critical_capability(
    client: Neo4jClient,
    config: AnalysisConfig,
    policy: PolicyConfig | None = None,
) -> list[Finding]:
    policy = policy or PolicyConfig()
    depth = config.max_tool_invocation_depth
    cypher = (
        "MATCH path = "
        "(source:ContextSource)-[:CONSUMED_BY]->"
        "(agent:Agent)-[:CAN_INVOKE*1.." + str(depth) + "]->"
        "(tool:Tool)-[:EXPOSES_CAPABILITY]->"
        "(capability:Capability) "
        "WHERE source.trust_level <= $low_trust_max "
        "AND capability.severity >= $critical_severity "
        "RETURN source, capability, path"
    )
    rows = client.run_query(
        cypher,
        low_trust_max=policy.low_trust_max,
        critical_severity=policy.critical_severity,
    )
    findings: list[Finding] = []
    seen: set[tuple[str, str]] = set()
    for row in rows:
        src = row["source"]
        cap = row["capability"]
        key = (src["id"], cap["id"])
        if key in seen:
            continue
        seen.add(key)
        full_path = _path_node_ids(row["path"])
        if not _within_path_length(full_path, config):
            continue
        agent_id = full_path[1] if len(full_path) > 1 else src["id"]
        findings.append(Finding(
            rule_id="R001",
            title="Low-trust context reaches critical capability",
            description=(
                f"Low-trust context '{src['id']}' can reach "
                f"capability '{cap['id']}' (severity {cap['severity']})"
            ),
            severity=FindingSeverity.CRITICAL
            if cap["severity"] > policy.critical_severity
            else FindingSeverity.HIGH,
            path=full_path,
            entities={
                "context_source": src["id"],
                "agent": agent_id,
                "capability": cap["id"],
            },
            recommended_control=RECOMMENDED_CONTROLS["R001"],
        ))
    return findings


def low_trust_to_sensitive_resource(
    client: Neo4jClient,
    config: AnalysisConfig,
    policy: PolicyConfig | None = None,
) -> list[Finding]:
    policy = policy or PolicyConfig()
    depth = config.max_tool_invocation_depth
    cypher = (
        "MATCH path = "
        "(source:ContextSource)-[:CONSUMED_BY]->"
        "(agent:Agent)-[:CAN_INVOKE*1.." + str(depth) + "]->"
        "(tool:Tool)-[:EXPOSES_CAPABILITY]->"
        "(capability:Capability)-[:CAN_ACCESS_RESOURCE]->"
        "(resource:Resource) "
        "WHERE source.trust_level <= $low_trust_max "
        "AND resource.sensitivity >= $sensitive_sensitivity "
        "RETURN source, capability, resource, path"
    )
    rows = client.run_query(
        cypher,
        low_trust_max=policy.low_trust_max,
        sensitive_sensitivity=policy.sensitive_sensitivity,
    )
    findings: list[Finding] = []
    seen: set[tuple[str, str]] = set()
    for row in rows:
        src = row["source"]
        res = row["resource"]
        cap = row["capability"]
        key = (src["id"], res["id"])
        if key in seen:
            continue
        seen.add(key)
        full_path = _path_node_ids(row["path"])
        if not _within_path_length(full_path, config):
            continue
        agent_id = full_path[1] if len(full_path) > 1 else src["id"]
        findings.append(Finding(
            rule_id="R002",
            title="Low-trust context reaches sensitive resource",
            description=(
                f"Low-trust context '{src['id']}' can reach "
                f"resource '{res['id']}' (sensitivity {res['sensitivity']}) "
                f"via capability '{cap['id']}'"
            ),
            severity=FindingSeverity.CRITICAL
            if res["sensitivity"] > policy.sensitive_sensitivity
            else FindingSeverity.HIGH,
            path=full_path,
            entities={
                "context_source": src["id"],
                "agent": agent_id,
                "capability": cap["id"],
                "resource": res["id"],
            },
            recommended_control=RECOMMENDED_CONTROLS["R002"],
        ))
    return findings


def dangerous_capability_composition(
    client: Neo4jClient,
    config: AnalysisConfig,
    policy: PolicyConfig | None = None,
) -> list[Finding]:
    policy = policy or PolicyConfig()
    depth = config.max_tool_invocation_depth
    cypher = (
        "MATCH "
        "(agent:Agent)-[:CAN_INVOKE*1.." + str(depth) + "]->"
        "(:Tool)-[:EXPOSES_CAPABILITY]->"
        "(cap1:Capability), "
        "(agent)-[:CAN_INVOKE*1.." + str(depth) + "]->"
        "(:Tool)-[:EXPOSES_CAPABILITY]->"
        "(cap2:Capability) "
        "WHERE [cap1.id, cap2.id] IN $pairs "
        "RETURN DISTINCT agent, cap1, cap2"
    )
    rows = client.run_query(
        cypher,
        pairs=[list(pair) for pair in policy.dangerous_pairs],
    )
    findings: list[Finding] = []
    seen: set[tuple[str, str, str]] = set()
    for row in rows:
        agent = row["agent"]
        cap1 = row["cap1"]
        cap2 = row["cap2"]
        key = (agent["id"], cap1["id"], cap2["id"])
        if key in seen:
            continue
        seen.add(key)
        path = [agent["id"], cap1["id"], cap2["id"]]
        if not _within_path_length(path, config):
            continue
        findings.append(Finding(
            rule_id="R003",
            title="Dangerous capability composition",
            description=(
                f"Agent '{agent['id']}' can reach both "
                f"'{cap1['id']}' and '{cap2['id']}'"
            ),
            severity=FindingSeverity.HIGH,
            path=path,
            entities={
                "agent": agent["id"],
                "capability_a": cap1["id"],
                "capability_b": cap2["id"],
            },
            recommended_control=RECOMMENDED_CONTROLS["R003"],
        ))
    return findings


def overprivileged_mcp_exposure(
    client: Neo4jClient,
    config: AnalysisConfig,
    policy: PolicyConfig | None = None,
) -> list[Finding]:
    policy = policy or PolicyConfig()
    threshold = config.overexposure_agent_threshold
    depth = config.max_tool_invocation_depth
    cypher = (
        "MATCH (agent:Agent)-[:CAN_INVOKE*1.." + str(depth) + "]->"
        "(tool:Tool)-[:USES_SERVER]->(server:MCPServer), "
        "(tool)-[:EXPOSES_CAPABILITY]->(cap:Capability) "
        "WHERE cap.severity >= $critical_severity "
        "WITH server, collect(DISTINCT agent.id) AS agents "
        "WHERE size(agents) >= $threshold "
        "RETURN server, agents"
    )
    rows = client.run_query(
        cypher,
        threshold=threshold,
        critical_severity=policy.critical_severity,
    )
    findings: list[Finding] = []
    for row in rows:
        server = row["server"]
        agents = row["agents"]
        findings.append(Finding(
            rule_id="R004",
            title="Overprivileged MCP exposure",
            description=(
                f"MCP server '{server['id']}' backs critical tools "
                f"invokable by {len(agents)} agents "
                f"(threshold: {threshold})"
            ),
            severity=FindingSeverity.HIGH,
            path=[server["id"]] + sorted(agents),
            entities={
                "mcp_server": server["id"],
                "agent_count": str(len(agents)),
            },
            recommended_control=RECOMMENDED_CONTROLS["R004"],
        ))
    return findings


def trust_boundary_crossing(
    client: Neo4jClient,
    config: AnalysisConfig,
    policy: PolicyConfig | None = None,
) -> list[Finding]:
    policy = policy or PolicyConfig()
    depth = config.max_tool_invocation_depth
    cypher = (
        "MATCH path = "
        "(source:ContextSource)-[:CONSUMED_BY]->"
        "(agent:Agent)-[:CAN_INVOKE*1.." + str(depth) + "]->"
        "(tool:Tool)-[:EXPOSES_CAPABILITY]->"
        "(capability:Capability) "
        "WHERE agent.trust_level > $low_trust_max "
        "AND source.trust_level <= $low_trust_max "
        "AND capability.severity >= $critical_severity "
        "RETURN source, agent, capability, path"
    )
    rows = client.run_query(
        cypher,
        low_trust_max=policy.low_trust_max,
        critical_severity=policy.critical_severity,
    )
    findings: list[Finding] = []
    seen: set[tuple[str, str, str]] = set()
    for row in rows:
        src = row["source"]
        agent = row["agent"]
        cap = row["capability"]
        key = (src["id"], agent["id"], cap["id"])
        if key in seen:
            continue
        seen.add(key)
        full_path = _path_node_ids(row["path"])
        if not _within_path_length(full_path, config):
            continue
        findings.append(Finding(
            rule_id="R005",
            title="Trust boundary crossing",
            description=(
                f"Low-trust context '{src['id']}' enters "
                f"higher-trust agent '{agent['id']}' "
                f"(trust_level {agent['trust_level']}) "
                f"with critical downstream capability '{cap['id']}'"
            ),
            severity=FindingSeverity.CRITICAL,
            path=full_path,
            entities={
                "context_source": src["id"],
                "agent": agent["id"],
                "capability": cap["id"],
            },
            recommended_control=RECOMMENDED_CONTROLS["R005"],
        ))
    return findings


ALL_CYPHER_RULES = [
    low_trust_to_critical_capability,
    low_trust_to_sensitive_resource,
    dangerous_capability_composition,
    overprivileged_mcp_exposure,
    trust_boundary_crossing,
]


def run_all_cypher_rules(
    client: Neo4jClient,
    config: AnalysisConfig,
    policy: PolicyConfig | None = None,
) -> list[Finding]:
    findings: list[Finding] = []
    for rule in ALL_CYPHER_RULES:
        findings.extend(rule(client, config, policy))
    findings.sort(key=lambda f: (f.rule_id, f.path))
    return findings
