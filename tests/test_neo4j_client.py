import pytest

from cognigraph.neo4j.client import Neo4jClient


pytestmark = pytest.mark.neo4j


class TestNeo4jClient:
    def test_node_count(self, neo4j_client: Neo4jClient):
        assert neo4j_client.node_count() == 12

    def test_edge_count(self, neo4j_client: Neo4jClient):
        assert neo4j_client.edge_count() == 11

    def test_context_source_loaded(self, neo4j_client: Neo4jClient):
        rows = neo4j_client.run_query(
            "MATCH (n:ContextSource) RETURN n.id AS id, n.trust_level AS trust_level"
        )
        assert len(rows) == 1
        assert rows[0]["id"] == "external_webpage"
        assert rows[0]["trust_level"] == 0

    def test_agent_loaded(self, neo4j_client: Neo4jClient):
        rows = neo4j_client.run_query(
            "MATCH (n:Agent) RETURN n.id AS id, n.trust_level AS trust_level"
        )
        assert len(rows) == 1
        assert rows[0]["id"] == "planner_agent"
        assert rows[0]["trust_level"] == 2

    def test_tools_loaded(self, neo4j_client: Neo4jClient):
        rows = neo4j_client.run_query("MATCH (n:Tool) RETURN n.id AS id")
        ids = {r["id"] for r in rows}
        assert ids == {"filesystem_tool", "github_tool"}

    def test_capabilities_loaded(self, neo4j_client: Neo4jClient):
        rows = neo4j_client.run_query(
            "MATCH (n:Capability) RETURN n.id AS id, n.severity AS severity"
        )
        assert len(rows) == 4
        caps = {r["id"]: r["severity"] for r in rows}
        assert caps["SecretRead"] == 4
        assert caps["FilesystemRead"] == 3

    def test_consumed_by_edges(self, neo4j_client: Neo4jClient):
        rows = neo4j_client.run_query(
            "MATCH (cs:ContextSource)-[:CONSUMED_BY]->(a:Agent) "
            "RETURN cs.id AS source, a.id AS target"
        )
        assert len(rows) == 1
        assert rows[0]["source"] == "external_webpage"
        assert rows[0]["target"] == "planner_agent"

    def test_can_invoke_edges(self, neo4j_client: Neo4jClient):
        rows = neo4j_client.run_query(
            "MATCH (a:Agent)-[:CAN_INVOKE]->(t:Tool) "
            "RETURN a.id AS agent, t.id AS tool"
        )
        tools = {r["tool"] for r in rows}
        assert tools == {"filesystem_tool", "github_tool"}

    def test_uses_server_edges(self, neo4j_client: Neo4jClient):
        rows = neo4j_client.run_query(
            "MATCH (t:Tool)-[:USES_SERVER]->(s:MCPServer) "
            "RETURN t.id AS tool, s.id AS server"
        )
        assert len(rows) == 2

    def test_clear(self, neo4j_client: Neo4jClient):
        neo4j_client.clear()
        assert neo4j_client.node_count() == 0
        assert neo4j_client.edge_count() == 0
