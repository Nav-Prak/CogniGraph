# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project

CogniGraph: graph-native capability reachability analysis for agentic AI systems. Loads a YAML fixture describing agents/tools/MCP servers/capabilities/resources, builds a directed privilege graph, and runs detection rules to find dangerous paths (e.g. low-trust web content reaching secret access). Package name is `cognigraph` (in `src/cognigraph/`), even though the repo directory is Hound-AI.

## Commands

Uses `uv` for everything (no requirements.txt; deps in `pyproject.toml` + `uv.lock`).

```bash
uv sync                                          # install
uv run pytest                                    # full suite (Neo4j tests auto-skip if no container)
uv run pytest tests/test_rules.py                # single file
uv run pytest tests/test_rules.py::test_name     # single test
uv run pytest -m neo4j                           # Neo4j integration tests only
uv run pytest --cov=cognigraph --cov-report=term-missing   # coverage (gate: fail_under=95)
docker compose up -d                             # start Neo4j (bolt://localhost:7687, neo4j/cognigraph)
uv run cognigraph examples/rag_mcp_vulnerable.yaml          # run the CLI
```

There is no linter/formatter configured.

Coverage intentionally omits `src/cognigraph/neo4j/*` (optional adapter requiring a running container); the 95% gate applies to the core in-memory path.

CLI exit codes: `0` = no findings, `1` = error, `2` = findings detected (more precisely: active finding groups at/above `--fail-on`, after suppressions). Tests assert on these.

## Architecture

The core is a linear pipeline, visible in `cli.py:main`:

```
YAML fixture → fixture/loader.load_fixture → graph/builder.build_from_fixture → rules/engine.run_all_rules → report/export
```

1. **`fixture/`** — Pydantic models (`models.py`) parse the YAML; `loader.py` then runs cross-reference validation (`validate_references`): every ID referenced in `consumes`/`can_invoke`/`capabilities`/`capability_bindings` must exist, raising `FixtureValidationError`. Optional `--annotations` files merge extra tool capabilities into the config (`apply_tool_annotations`) and are re-validated after merging.

2. **`graph/builder.py`** — `CogniGraph` wraps a NetworkX `DiGraph`. Node/edge data lives in graph attributes (`node_type`, `trust_level`, `severity`, `sensitivity`, `edge_type`). `add_edge` enforces the edge-type whitelist and raises `InvalidEdgeError` on violations.

3. **`schemas/`** — the single source of truth for the domain model: `enums.py` (NodeType, EdgeType, trust levels), `edges.py` (`ALLOWED_RELATIONSHIPS` — the (source type, edge type) → allowed target types table that gates all edge creation), `nodes.py`, `findings.py` (the `Finding` model with rule_id, severity, path, entities, recommended_control).

4. **`rules/engine.py`** — five detection rules R001–R005, each a standalone function returning `list[Finding]`; `run_all_rules` aggregates. Reachability is BFS over `CAN_INVOKE` edges bounded by `analysis.max_tool_invocation_depth` and `max_path_length` from the fixture. Thresholds and dangerous pairs come from the fixture's optional `policy` block (`PolicyConfig` in `fixture/models.py`; defaults preserve legacy behavior). `rules/grouping.py` post-processes findings into per-(rule, target) groups and applies the `--suppressions` file; the CLI exit code is decided by active groups vs `--fail-on`, never by raw findings.

5. **`neo4j/`** — optional adapter. **`neo4j/queries.py` mirrors all five rules in Cypher and must produce identical findings to the in-memory engine** — changing a rule means changing it in both places. `tests/conftest.py` skips Neo4j tests when the container isn't reachable.

6. **`trace/`** — runtime trace overlay (preview feature, not core MVP). Overlays a JSON event trace onto the static graph: direct events mark static edges as exercised, tool→resource events are projected onto capability paths, unmatched events become "runtime-only" edges. Format-specific parsing lives in `trace/adapters/` (registry keyed by `--trace-format`; `internal-json` and `otlp-json` ship today) — new trace sources are new adapters, never changes to the core loader.

7. **`collect/`** — collectors that turn real MCP client configs (`claude_desktop_config.json`, `.mcp.json`, VS Code `.vscode/mcp.json`) into fixture skeletons via the `cognigraph collect` subcommand. Strict one-way boundary: `collect` imports `fixture.models` and emits fixtures (never findings); nothing in the analyzer imports `collect`. Collectors must stay deterministic — structure from the config, capability semantics only via annotations/heuristics.

8. **Output**: `export.py` (DOT with finding paths highlighted, graph JSON), `report.py` (text report, findings JSON, static HTML report).

## Conventions

- Detection rules and the README's rules table must stay in sync; `examples/` fixtures encode expected findings per fixture (asserted in `tests/test_examples.py` and `tests/test_acceptance.py`).
- Trust levels are 0–4 (0 = untrusted, 1 = low; rules treat `<= 1` as low-trust). Capability `severity` and resource `sensitivity` are 1–4; rules treat `>= 3` as critical/sensitive.
- `local_notes/` is git-ignored scratch space — don't rely on or modify it.
