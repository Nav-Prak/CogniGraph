import json
import sys
from pathlib import Path

import pytest

from cognigraph.cli import main
from cognigraph.collect.introspect import (
    IntrospectedTool,
    _transport_kind,
    ensure_introspection_available,
    introspect_server,
)
from cognigraph.collect.mcp_config import (
    CollectError,
    IntrospectionUnavailableError,
    collect_from_mcp_config,
)

STUB_SERVER = Path(__file__).resolve().parent / "mcp_stub_server.py"


def write_config(tmp_path: Path, data) -> Path:
    path = tmp_path / "config.json"
    path.write_text(json.dumps(data), encoding="utf-8")
    return path


def stub_server_config(tmp_path: Path) -> Path:
    return write_config(
        tmp_path,
        {
            "mcpServers": {
                "stub": {
                    "command": sys.executable,
                    "args": [str(STUB_SERVER)],
                }
            }
        },
    )


class TestCollectWithIntrospector:
    """Unit tests with a fake introspector; no MCP server involved."""

    def test_per_tool_nodes_replace_stub(self, tmp_path):
        config_path = write_config(
            tmp_path, {"mcpServers": {"filesystem": {"command": "fs-mcp"}}}
        )
        fake = lambda name, entry: [
            IntrospectedTool("read_file", "Read file contents."),
            IntrospectedTool("write_file", "Write file contents."),
        ]
        config = collect_from_mcp_config(config_path, introspector=fake)
        tool_ids = {t.id for t in config.tools}
        assert tool_ids == {"filesystem_read_file", "filesystem_write_file"}
        assert all(t.mcp_server == "filesystem" for t in config.tools)
        assert set(config.agents[0].can_invoke) == tool_ids

    def test_descriptions_record_tool_and_server(self, tmp_path):
        config_path = write_config(
            tmp_path, {"mcpServers": {"fs": {"command": "fs-mcp"}}}
        )
        fake = lambda name, entry: [
            IntrospectedTool("read_file", "Read file contents."),
            IntrospectedTool("undocumented"),
        ]
        config = collect_from_mcp_config(config_path, introspector=fake)
        by_id = {t.id: t for t in config.tools}
        assert (
            by_id["fs_read_file"].description
            == "Tool 'read_file' on MCP server 'fs': Read file contents."
        )
        assert (
            by_id["fs_undocumented"].description
            == "Tool 'undocumented' on MCP server 'fs'"
        )

    def test_failed_server_degrades_to_stub_with_warning(self, tmp_path):
        config_path = write_config(
            tmp_path,
            {
                "mcpServers": {
                    "good": {"command": "good-mcp"},
                    "bad": {"command": "bad-mcp"},
                }
            },
        )

        def fake(name, entry):
            if name == "bad":
                raise CollectError("connection refused")
            return [IntrospectedTool("search", "Search the index.")]

        warnings: list[str] = []
        config = collect_from_mcp_config(
            config_path, introspector=fake, warn=warnings.append
        )
        tool_ids = {t.id for t in config.tools}
        assert tool_ids == {"good_search", "bad_tool"}
        assert len(warnings) == 1
        assert "bad" in warnings[0] and "stub" in warnings[0]

    def test_empty_tool_list_warns_and_emits_no_tools(self, tmp_path):
        config_path = write_config(
            tmp_path, {"mcpServers": {"idle": {"command": "idle-mcp"}}}
        )
        warnings: list[str] = []
        config = collect_from_mcp_config(
            config_path,
            introspector=lambda name, entry: [],
            warn=warnings.append,
        )
        assert config.tools == []
        assert config.agents[0].can_invoke == []
        assert any("reported no tools" in w for w in warnings)

    def test_unavailable_sdk_propagates(self, tmp_path):
        config_path = write_config(
            tmp_path, {"mcpServers": {"fs": {"command": "fs-mcp"}}}
        )

        def fake(name, entry):
            raise IntrospectionUnavailableError("mcp not installed")

        with pytest.raises(IntrospectionUnavailableError):
            collect_from_mcp_config(config_path, introspector=fake)

    def test_tool_names_sanitized_and_uniquified(self, tmp_path):
        config_path = write_config(
            tmp_path, {"mcpServers": {"srv": {"command": "x"}}}
        )
        fake = lambda name, entry: [
            IntrospectedTool("read file!"),
            IntrospectedTool("read-file"),
        ]
        config = collect_from_mcp_config(config_path, introspector=fake)
        assert {t.id for t in config.tools} == {
            "srv_read_file",
            "srv_read_file_2",
        }


class TestTransportKind:
    def test_stdio(self):
        assert _transport_kind({"command": "x"}) == "stdio"

    def test_http_default_for_url(self):
        assert _transport_kind({"url": "https://example/mcp"}) == "http"
        assert (
            _transport_kind({"type": "http", "url": "https://example/mcp"})
            == "http"
        )

    def test_sse(self):
        assert (
            _transport_kind({"type": "sse", "url": "https://example/sse"})
            == "sse"
        )

    def test_neither_raises(self):
        with pytest.raises(CollectError, match="neither 'command' nor 'url'"):
            _transport_kind({})


class TestAvailability:
    def test_available_when_sdk_installed(self):
        pytest.importorskip("mcp")
        ensure_introspection_available()

    def test_missing_sdk_raises_install_hint(self, monkeypatch):
        monkeypatch.setattr(
            "cognigraph.collect.introspect.importlib_util.find_spec",
            lambda name: None,
        )
        with pytest.raises(
            IntrospectionUnavailableError, match=r"cognigraph\[introspect\]"
        ):
            ensure_introspection_available()

    def test_cli_introspect_without_sdk_errors(self, monkeypatch, capsys, tmp_path):
        monkeypatch.setattr(
            "cognigraph.collect.introspect.importlib_util.find_spec",
            lambda name: None,
        )
        config_path = write_config(
            tmp_path, {"mcpServers": {"fs": {"command": "fs-mcp"}}}
        )
        rc = main(["collect", str(config_path), "--introspect"])
        assert rc == 1
        assert "cognigraph[introspect]" in capsys.readouterr().err


class TestLiveIntrospection:
    """Integration tests that spawn the stdio stub server."""

    @pytest.fixture(autouse=True)
    def _require_mcp(self):
        pytest.importorskip("mcp")

    def test_introspect_server_lists_real_tools(self):
        entry = {"command": sys.executable, "args": [str(STUB_SERVER)]}
        tools = introspect_server("stub", entry, timeout=30)
        by_name = {tool.name: tool for tool in tools}
        assert set(by_name) == {"read_file", "send_email"}
        assert "filesystem" in by_name["read_file"].description.lower()

    def test_unreachable_command_raises_collect_error(self):
        entry = {"command": sys.executable, "args": ["-c", "raise SystemExit(1)"]}
        with pytest.raises(CollectError, match="stub-broken|could not|answer"):
            introspect_server("stub-broken", entry, timeout=5)

    def test_timeout_raises_collect_error(self):
        # A process that never speaks MCP: initialize hangs until timeout.
        entry = {
            "command": sys.executable,
            "args": ["-c", "import time; time.sleep(60)"],
        }
        with pytest.raises(CollectError, match="did not answer"):
            introspect_server("stub-slow", entry, timeout=1)

    def test_cli_collect_introspect_to_findings(self, tmp_path, capsys):
        config_path = stub_server_config(tmp_path)
        fixture_path = tmp_path / "fixture.yaml"
        rc = main(
            [
                "collect",
                str(config_path),
                "--introspect",
                "-o",
                str(fixture_path),
            ]
        )
        assert rc == 0
        err = capsys.readouterr().err
        assert "1 server(s), 2 tool(s)" in err

        # Real tool descriptions feed the heuristic mapper: read_file ->
        # FilesystemRead (severity 3) reachable from low-trust user_input.
        rc = main([str(fixture_path), "--infer-capabilities", "--quiet"])
        assert rc == 2

    def test_cli_warns_and_keeps_stub_for_failed_server(self, tmp_path, capsys):
        config_path = write_config(
            tmp_path,
            {
                "mcpServers": {
                    "stub": {
                        "command": sys.executable,
                        "args": [str(STUB_SERVER)],
                    },
                    "broken": {
                        "command": sys.executable,
                        "args": ["-c", "raise SystemExit(1)"],
                    },
                }
            },
        )
        rc = main(["collect", str(config_path), "--introspect"])
        captured = capsys.readouterr()
        assert rc == 0
        assert "Warning: Introspection failed for server 'broken'" in captured.err
        assert "stub_read_file" in captured.out
        assert "broken_tool" in captured.out
