from __future__ import annotations

from neo4j import GraphDatabase

from cognigraph.fixture.models import FixtureConfig
from cognigraph.schemas.enums import EdgeType, NodeType


class Neo4jClient:
    def __init__(self, uri: str, user: str, password: str) -> None:
        self._driver = GraphDatabase.driver(uri, auth=(user, password))

    def close(self) -> None:
        self._driver.close()

    def __enter__(self) -> Neo4jClient:
        return self

    def __exit__(self, *args: object) -> None:
        self.close()

    def clear(self) -> None:
        with self._driver.session() as session:
            session.run("MATCH (n) DETACH DELETE n")

    def load_fixture(self, config: FixtureConfig) -> None:
        with self._driver.session() as session:
            for cs in config.context_sources:
                session.run(
                    "CREATE (n:ContextSource {id: $id, trust_level: $trust_level, source_type: $source_type})",
                    id=cs.id, trust_level=cs.trust_level, source_type=cs.source_type.value,
                )

            for agent in config.agents:
                session.run(
                    "CREATE (n:Agent {id: $id, trust_level: $trust_level})",
                    id=agent.id, trust_level=agent.trust_level,
                )

            for tool in config.tools:
                session.run(
                    "CREATE (n:Tool {id: $id, mcp_server: $mcp_server})",
                    id=tool.id, mcp_server=tool.mcp_server,
                )

            for server in config.mcp_servers:
                session.run(
                    "CREATE (n:MCPServer {id: $id})",
                    id=server.id,
                )

            for cap in config.capabilities:
                session.run(
                    "CREATE (n:Capability {id: $id, severity: $severity, resource_binding_required: $rbr})",
                    id=cap.id, severity=cap.severity, rbr=cap.resource_binding_required,
                )

            for res in config.resources:
                session.run(
                    "CREATE (n:Resource {id: $id, resource_type: $resource_type, sensitivity: $sensitivity})",
                    id=res.id, resource_type=res.type.value, sensitivity=res.sensitivity,
                )

            for agent in config.agents:
                for cs_id in agent.consumes:
                    session.run(
                        "MATCH (cs:ContextSource {id: $cs_id}), (a:Agent {id: $agent_id}) "
                        "CREATE (cs)-[:CONSUMED_BY]->(a)",
                        cs_id=cs_id, agent_id=agent.id,
                    )
                for tool_id in agent.can_invoke:
                    session.run(
                        "MATCH (a:Agent {id: $agent_id}), (t:Tool {id: $tool_id}) "
                        "CREATE (a)-[:CAN_INVOKE]->(t)",
                        agent_id=agent.id, tool_id=tool_id,
                    )

            for tool in config.tools:
                for invoked_id in tool.can_invoke:
                    session.run(
                        "MATCH (t1:Tool {id: $tool_id}), (t2:Tool {id: $invoked_id}) "
                        "CREATE (t1)-[:CAN_INVOKE]->(t2)",
                        tool_id=tool.id, invoked_id=invoked_id,
                    )
                for cap_id in tool.capabilities:
                    session.run(
                        "MATCH (t:Tool {id: $tool_id}), (c:Capability {id: $cap_id}) "
                        "CREATE (t)-[:EXPOSES_CAPABILITY]->(c)",
                        tool_id=tool.id, cap_id=cap_id,
                    )
                if tool.mcp_server:
                    session.run(
                        "MATCH (t:Tool {id: $tool_id}), (s:MCPServer {id: $server_id}) "
                        "CREATE (t)-[:USES_SERVER]->(s)",
                        tool_id=tool.id, server_id=tool.mcp_server,
                    )

            for binding in config.capability_bindings:
                session.run(
                    "MATCH (c:Capability {id: $cap_id}), (r:Resource {id: $res_id}) "
                    "CREATE (c)-[:CAN_ACCESS_RESOURCE]->(r)",
                    cap_id=binding.capability, res_id=binding.resource,
                )

    def node_count(self) -> int:
        with self._driver.session() as session:
            result = session.run("MATCH (n) RETURN count(n) AS count")
            return result.single()["count"]

    def edge_count(self) -> int:
        with self._driver.session() as session:
            result = session.run("MATCH ()-[r]->() RETURN count(r) AS count")
            return result.single()["count"]

    def run_query(self, cypher: str, **params: object) -> list[dict]:
        with self._driver.session() as session:
            result = session.run(cypher, **params)
            return [dict(record) for record in result]
