import json
from pathlib import Path

import pytest

from cognigraph.cli import main
from cognigraph.collect.mcp_config import (
    SEEDED_CAPABILITIES,
    CollectError,
    collect_from_mcp_config,
    fixture_to_yaml,
)
from cognigraph.fixture.loader import load_fixture

FIXTURES_DIR = Path(__file__).resolve().parent.parent / "fixtures"
SAMPLE_CONFIG = FIXTURES_DIR / "sample_mcp_config.json"


def write_config(tmp_path: Path, data, name: str = "config.json") -> Path:
    path = tmp_path / name
    path.write_text(
        data if isinstance(data, str) else json.dumps(data), encoding="utf-8"
    )
    return path


class TestCollectFromMcpConfig:
    def test_sample_config_servers_and_tools(self):
        config = collect_from_mcp_config(SAMPLE_CONFIG)
        server_ids = {s.id for s in config.mcp_servers}
        assert server_ids == {"filesystem", "github", "internal_search"}
        tool_ids = {t.id for t in config.tools}
        assert tool_ids == {
            "filesystem_tool",
            "github_tool",
            "internal_search_tool",
        }
        for tool in config.tools:
            assert tool.mcp_server in server_ids
            assert tool.capabilities == []

    def test_host_agent_invokes_all_tools(self):
        config = collect_from_mcp_config(SAMPLE_CONFIG)
        assert len(config.agents) == 1
        agent = config.agents[0]
        assert agent.id == "host_agent"
        assert agent.trust_level == 2
        assert agent.consumes == ["user_input"]
        assert set(agent.can_invoke) == {t.id for t in config.tools}

    def test_context_source_default(self):
        config = collect_from_mcp_config(SAMPLE_CONFIG)
        assert len(config.context_sources) == 1
        cs = config.context_sources[0]
        assert cs.id == "user_input"
        assert cs.trust_level == 1

    def test_descriptions_record_command_and_url(self):
        config = collect_from_mcp_config(SAMPLE_CONFIG)
        by_id = {t.id: t for t in config.tools}
        assert "stdio" in by_id["filesystem_tool"].description
        assert "server-filesystem" in by_id["filesystem_tool"].description
        assert "http" in by_id["internal_search_tool"].description
        assert (
            "https://mcp.example.internal/search"
            in by_id["internal_search_tool"].description
        )

    def test_seeded_capabilities(self):
        config = collect_from_mcp_config(SAMPLE_CONFIG)
        cap_ids = {c.id for c in config.capabilities}
        assert cap_ids == {c["id"] for c in SEEDED_CAPABILITIES}
        severities = {c.id: c.severity for c in config.capabilities}
        assert severities["SecretRead"] == 4
        assert severities["ExternalNetworkSend"] == 3

    def test_no_seed_capabilities(self):
        config = collect_from_mcp_config(SAMPLE_CONFIG, seed_capabilities=False)
        assert config.capabilities == []

    def test_custom_agent(self):
        config = collect_from_mcp_config(
            SAMPLE_CONFIG, agent_id="claude_desktop", agent_trust_level=3
        )
        assert config.agents[0].id == "claude_desktop"
        assert config.agents[0].trust_level == 3

    def test_vscode_servers_key(self, tmp_path):
        path = write_config(
            tmp_path,
            {
                "servers": {
                    "remote-api": {"type": "sse", "url": "http://api.example/sse"}
                }
            },
        )
        config = collect_from_mcp_config(path)
        assert config.mcp_servers[0].id == "remote_api"

    def test_jsonc_comments_and_trailing_commas(self, tmp_path):
        text = """
        {
          // VS Code style config
          "servers": {
            "demo": {
              "type": "http",
              "url": "https://example.com/mcp", /* note the // in the url */
            },
          },
        }
        """
        path = write_config(tmp_path, text)
        config = collect_from_mcp_config(path)
        assert config.mcp_servers[0].id == "demo"
        assert "https://example.com/mcp" in config.tools[0].description

    def test_sanitizes_and_uniquifies_ids(self, tmp_path):
        path = write_config(
            tmp_path,
            {
                "mcpServers": {
                    "my server!": {"command": "a"},
                    "my-server": {"command": "b"},
                    "123weird": {"command": "c"},
                }
            },
        )
        config = collect_from_mcp_config(path)
        ids = [s.id for s in config.mcp_servers]
        assert len(set(ids)) == 3
        assert "my_server" in ids
        assert "my_server_2" in ids
        assert "s_123weird" in ids

    def test_missing_file(self, tmp_path):
        with pytest.raises(CollectError, match="Could not read config file"):
            collect_from_mcp_config(tmp_path / "nope.json")

    def test_invalid_json(self, tmp_path):
        path = write_config(tmp_path, "not json")
        with pytest.raises(CollectError, match="Invalid JSON"):
            collect_from_mcp_config(path)

    def test_non_object_json(self, tmp_path):
        path = write_config(tmp_path, "[1, 2]")
        with pytest.raises(CollectError, match="Expected a JSON object"):
            collect_from_mcp_config(path)

    def test_missing_servers_key(self, tmp_path):
        path = write_config(tmp_path, {"theme": "dark"})
        with pytest.raises(CollectError, match="No 'mcpServers' or 'servers'"):
            collect_from_mcp_config(path)

    def test_empty_servers(self, tmp_path):
        path = write_config(tmp_path, {"mcpServers": {}})
        with pytest.raises(CollectError, match="declares no MCP servers"):
            collect_from_mcp_config(path)

    def test_non_object_server_entry(self, tmp_path):
        path = write_config(tmp_path, {"mcpServers": {"bad": "string"}})
        with pytest.raises(CollectError, match="is not an object"):
            collect_from_mcp_config(path)

    def test_escaped_quotes_survive_jsonc_strip(self, tmp_path):
        path = write_config(
            tmp_path,
            {
                "mcpServers": {
                    "echo": {"command": "echo", "args": ['say "hi" // not a comment']}
                }
            },
        )
        config = collect_from_mcp_config(path)
        assert 'say "hi" // not a comment' in config.tools[0].description

    def test_fully_symbolic_name_falls_back(self, tmp_path):
        path = write_config(tmp_path, {"mcpServers": {"!!!": {"command": "x"}}})
        config = collect_from_mcp_config(path)
        assert config.mcp_servers[0].id == "server"

    def test_entry_without_command_or_url(self, tmp_path):
        path = write_config(tmp_path, {"mcpServers": {"mystery": {}}})
        config = collect_from_mcp_config(path)
        assert config.tools[0].description == "MCP server 'mystery'"


class TestFixtureRoundTrip:
    def test_emitted_yaml_loads_as_fixture(self, tmp_path):
        config = collect_from_mcp_config(SAMPLE_CONFIG)
        out = tmp_path / "fixture.yaml"
        out.write_text(fixture_to_yaml(config), encoding="utf-8")
        loaded = load_fixture(out)
        assert {s.id for s in loaded.mcp_servers} == {
            s.id for s in config.mcp_servers
        }
        assert {t.id for t in loaded.tools} == {t.id for t in config.tools}

    def test_collect_annotate_analyze_end_to_end(self, tmp_path):
        fixture_path = tmp_path / "fixture.yaml"
        rc = main(["collect", str(SAMPLE_CONFIG), "-o", str(fixture_path)])
        assert rc == 0

        annotations = tmp_path / "annotations.yaml"
        annotations.write_text(
            "tool_capability_annotations:\n"
            "  filesystem_tool:\n"
            "    capabilities:\n"
            "      - SecretRead\n"
            "  github_tool:\n"
            "    capabilities:\n"
            "      - ExternalNetworkSend\n",
            encoding="utf-8",
        )
        rc = main(
            [
                str(fixture_path),
                "--annotations",
                str(annotations),
                "--quiet",
            ]
        )
        assert rc == 2

    def test_collected_fixture_alone_has_no_findings(self, tmp_path, capsys):
        fixture_path = tmp_path / "fixture.yaml"
        assert main(["collect", str(SAMPLE_CONFIG), "-o", str(fixture_path)]) == 0
        capsys.readouterr()
        rc = main([str(fixture_path), "--quiet"])
        assert rc == 0


class TestCollectCLI:
    def test_stdout_output(self, capsys):
        rc = main(["collect", str(SAMPLE_CONFIG)])
        assert rc == 0
        out = capsys.readouterr().out
        assert "mcp_servers:" in out
        assert "filesystem_tool" in out

    def test_output_file_and_summary(self, tmp_path, capsys):
        out_path = tmp_path / "out.yaml"
        rc = main(["collect", str(SAMPLE_CONFIG), "-o", str(out_path)])
        assert rc == 0
        err = capsys.readouterr().err
        assert "3 server(s)" in err
        assert out_path.exists()

    def test_collect_error_exit_code(self, tmp_path, capsys):
        bad = write_config(tmp_path, "not json")
        rc = main(["collect", str(bad)])
        assert rc == 1
        assert "Error" in capsys.readouterr().err

    def test_no_seed_flag(self, capsys):
        rc = main(["collect", str(SAMPLE_CONFIG), "--no-seed-capabilities"])
        assert rc == 0
        out = capsys.readouterr().out
        assert "SecretRead" not in out

    def test_custom_agent_flags(self, capsys):
        rc = main(
            [
                "collect",
                str(SAMPLE_CONFIG),
                "--agent-id",
                "desktop_app",
                "--agent-trust-level",
                "3",
            ]
        )
        assert rc == 0
        out = capsys.readouterr().out
        assert "desktop_app" in out
        assert "trust_level: 3" in out
