from pathlib import Path

import pytest

from cognigraph.fixture.loader import load_fixture
from cognigraph.fixture.models import FixtureConfig
from cognigraph.graph.builder import CogniGraph, build_from_fixture

FIXTURES_DIR = Path(__file__).resolve().parent.parent / "fixtures"

NEO4J_URI = "bolt://localhost:7687"
NEO4J_USER = "neo4j"
NEO4J_PASSWORD = "cognigraph"


def neo4j_is_available() -> bool:
    try:
        from cognigraph.neo4j.client import Neo4jClient
        with Neo4jClient(NEO4J_URI, NEO4J_USER, NEO4J_PASSWORD) as client:
            client.node_count()
        return True
    except Exception:
        return False


@pytest.fixture
def sample_config() -> FixtureConfig:
    return load_fixture(FIXTURES_DIR / "sample_fixture.yaml")


@pytest.fixture
def sample_graph(sample_config: FixtureConfig) -> CogniGraph:
    return build_from_fixture(sample_config)


@pytest.fixture
def neo4j_client(sample_config: FixtureConfig):
    if not neo4j_is_available():
        pytest.skip("Neo4j is not available")
    from cognigraph.neo4j.client import Neo4jClient
    with Neo4jClient(NEO4J_URI, NEO4J_USER, NEO4J_PASSWORD) as client:
        client.clear()
        client.load_fixture(sample_config)
        yield client
        client.clear()
