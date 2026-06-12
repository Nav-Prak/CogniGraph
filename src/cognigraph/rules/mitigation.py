from __future__ import annotations

from cognigraph.fixture.models import FixtureConfig, PolicyNodeConfig
from cognigraph.graph.builder import CogniGraph
from cognigraph.schemas.enums import PolicyEffect
from cognigraph.schemas.findings import Finding, FindingSeverity


def _protected_node_ids(config: FixtureConfig) -> dict[str, PolicyNodeConfig]:
    """Map each protected node id to the policy covering it.

    A policy on an MCP server extends to every tool backed by that server,
    since those tools are the server's reachable surface.
    """
    server_ids = {s.id for s in config.mcp_servers}
    protected: dict[str, PolicyNodeConfig] = {}
    for policy in config.policies:
        for target_id in policy.applies_to:
            protected[target_id] = policy
            if target_id in server_ids:
                for tool in config.tools:
                    if tool.mcp_server == target_id:
                        protected[tool.id] = policy
    return protected


def _downgrade(severity: FindingSeverity) -> FindingSeverity:
    return FindingSeverity(max(severity - 1, FindingSeverity.INFO))


class _Gatekeeper:
    """Decides whether a finding's risk is fully gated by policies.

    The engine reports one path per (source, target), so checking only the
    recorded path is unsound: a protected tool's path can shadow an
    unprotected alternative. A capability counts as gated only when EVERY
    tool exposing it that the agent can reach is protected (or the agent
    itself is).
    """

    def __init__(self, graph: CogniGraph, config: FixtureConfig) -> None:
        self._graph = graph
        self._protected = _protected_node_ids(config)
        self._depth = config.analysis.max_tool_invocation_depth
        self._reachable_cache: dict[str, list[str]] = {}

    def _reachable_tools(self, agent_id: str) -> list[str]:
        if agent_id not in self._reachable_cache:
            self._reachable_cache[agent_id] = list(
                self._graph.get_reachable_with_paths(agent_id, self._depth)
            )
        return self._reachable_cache[agent_id]

    def _capability_gate(
        self, agent_id: str, capability_id: str
    ) -> PolicyNodeConfig | None:
        exposing = [
            tool_id
            for tool_id in self._reachable_tools(agent_id)
            if capability_id in self._graph.get_capabilities_of_tool(tool_id)
        ]
        if not exposing or any(t not in self._protected for t in exposing):
            return None
        return self._protected[sorted(exposing)[0]]

    def gate_for(self, finding: Finding) -> PolicyNodeConfig | None:
        agent_id = finding.entities.get("agent")
        if agent_id and agent_id in self._protected:
            return self._protected[agent_id]

        if finding.rule_id in ("R001", "R002", "R005"):
            return self._capability_gate(agent_id, finding.entities["capability"])
        if finding.rule_id == "R003":
            # Gating either half of the pair breaks the composition.
            return self._capability_gate(
                agent_id, finding.entities["capability_a"]
            ) or self._capability_gate(agent_id, finding.entities["capability_b"])
        if finding.rule_id == "R004":
            server_id = finding.entities["mcp_server"]
            if server_id in self._protected:
                return self._protected[server_id]
            agents = finding.path[1:]
            if agents and all(a in self._protected for a in agents):
                return self._protected[sorted(agents)[0]]
            return None
        # Unknown rules: conservative path-crossing fallback.
        return next(
            (self._protected[n] for n in finding.path if n in self._protected),
            None,
        )


def apply_policy_mitigations(
    graph: CogniGraph, config: FixtureConfig, findings: list[Finding]
) -> list[Finding]:
    """Mark or downgrade findings whose risk is fully gated by a policy.

    effect=mitigate: the finding keeps its severity but is marked mitigated
    (its group behaves like an accepted risk). effect=downgrade: severity
    drops one level and the finding stays active.
    """
    if not config.policies:
        return findings

    gatekeeper = _Gatekeeper(graph, config)
    result: list[Finding] = []
    for finding in findings:
        policy = gatekeeper.gate_for(finding)
        if policy is None:
            result.append(finding)
        elif policy.effect == PolicyEffect.MITIGATE:
            result.append(finding.model_copy(update={"mitigated_by": policy.id}))
        else:
            result.append(
                finding.model_copy(
                    update={"severity": _downgrade(finding.severity)}
                )
            )
    return result
