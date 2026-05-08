from pathlib import Path

import pytest

from cognigraph.fixture.loader import load_fixture
from cognigraph.fixture.models import FixtureConfig
from cognigraph.graph.builder import CogniGraph, build_from_fixture

FIXTURES_DIR = Path(__file__).resolve().parent.parent / "fixtures"


@pytest.fixture
def sample_config() -> FixtureConfig:
    return load_fixture(FIXTURES_DIR / "sample_fixture.yaml")


@pytest.fixture
def sample_graph(sample_config: FixtureConfig) -> CogniGraph:
    return build_from_fixture(sample_config)
