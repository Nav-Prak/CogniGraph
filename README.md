# CogniGraph

Graph-native capability reachability analysis for agentic AI systems.

Agentic AI systems compose LLM planners, MCP servers, tools, retrieval systems, and external APIs into complex capability topologies. CogniGraph models these as a directed graph and answers a single question:

> What dangerous capabilities can low-trust context reach?

It takes a YAML fixture describing your system's agents, tools, MCP servers, capabilities, and resources, builds a privilege graph, and runs detection rules to find dangerous paths, like untrusted web content reaching secret access, or a single agent having both secret-read and network-send capabilities.

## Prerequisites

- Python 3.11+
- [uv](https://docs.astral.sh/uv/) (Python package manager)
- Docker (optional, for Neo4j integration)

## Getting Started

```bash
# Clone and install
git clone <repo-url> && cd Hound-AI
uv sync

# Run the five-minute MVP demo
uv run cognigraph examples/rag_mcp_vulnerable.yaml --html-report report.html --findings-json findings.json
```

This loads a vulnerable RAG/MCP fixture, builds the graph, runs all detection rules, writes a static HTML report, and exports structured JSON findings. Open `report.html` to inspect the risky paths, node metadata, and recommended controls.

The CLI also prints a text report:

```
CogniGraph Analysis Report
==================================================
Total findings: 11
  CRITICAL: 7
  HIGH: 4
==================================================

--- Finding 1 ---
[R001] [CRITICAL] Low-trust context reaches critical capability
  Low-trust context 'external_webpage' can reach capability 'SecretRead' (severity 4)
  Path: external_webpage -> research_planner -> filesystem_tool -> SecretRead
  Recommended control: Restrict low-trust context from reaching this capability...
...
```

## MVP Examples

The `examples/` directory contains the core demo fixtures:

| Fixture | Purpose | Expected result |
|---------|---------|-----------------|
| `examples/rag_mcp_vulnerable.yaml` | Low-trust web/RAG context reaches secret, repository, and network capabilities | R001, R002, R003, and R005 findings |
| `examples/least_privilege_safe.yaml` | Low-trust input can only reach low-severity documentation search over low-sensitivity public docs | No findings |
| `examples/overexposed_mcp.yaml` | Three agents can invoke one MCP-backed critical capability with threshold set to `3` | R004 finding |

A safe fixture means no low-trust context can reach severity `>= 3` capabilities, no low-trust context can reach sensitivity `>= 3` resources, no agent can compose a configured dangerous capability pair, no MCP server exceeds the overexposure threshold, and no higher-trust agent consuming low-trust context has downstream critical capability access.

## CLI Usage

```bash
# Print findings report to stdout
uv run cognigraph examples/rag_mcp_vulnerable.yaml

# Export graph as Graphviz DOT (finding paths highlighted in red)
uv run cognigraph examples/rag_mcp_vulnerable.yaml --export-dot graph.dot

# Export graph as JSON
uv run cognigraph examples/rag_mcp_vulnerable.yaml --export-json graph.json

# Export findings as structured JSON
uv run cognigraph examples/rag_mcp_vulnerable.yaml --findings-json findings.json

# Export a static HTML report with finding paths and node metadata
uv run cognigraph examples/rag_mcp_vulnerable.yaml --html-report report.html

# Preview: overlay a simple runtime trace on the static graph
uv run cognigraph examples/rag_mcp_vulnerable.yaml --trace examples/runtime_trace_example.json --html-report report.html

# Suppress stdout report (useful when only exporting)
uv run cognigraph examples/rag_mcp_vulnerable.yaml --quiet --export-dot graph.dot

# Render the DOT file to PNG (requires Graphviz installed)
dot -Tpng graph.dot -o graph.png
```

Exit codes: `0` = no findings, `1` = error, `2` = findings detected.

Structured JSON findings include the rule ID, severity, path, entities, and deterministic `recommended_control` guidance.

## Runtime Trace Overlay Preview

CogniGraph has a small internal JSON trace format for runtime overlays. This is a preview feature, not a core MVP requirement. It is not a direct Observal or OpenTelemetry format yet; external trace systems should map into this internal format through adapters.

```json
{
  "trace_id": "trace-001",
  "events": [
    {
      "timestamp": "2026-05-01T10:00:00Z",
      "source_id": "external_webpage",
      "target_id": "research_planner",
      "edge_type": "PASSED_TO",
      "metadata": {"trigger": "rag_retrieval"}
    }
  ]
}
```

Supported runtime edge types:

| Runtime edge | Intended meaning |
|--------------|------------------|
| `PASSED_TO` | Context or data passed into an agent |
| `RETRIEVED_FROM` | Context retrieved from a source |
| `INVOKED` | Agent or tool invoked another tool |
| `READ_FROM` | Tool read from a resource |
| `WROTE_TO` | Tool wrote to a resource |
| `EXECUTED_IN` | Agent or tool executed in an environment |

Overlay semantics:

- Direct runtime events only mark static edges observed when the runtime edge type is compatible with the static edge.
- Tool-to-resource runtime events are projected onto declared capability paths when possible. For example, `filesystem_tool READ_FROM ssh_private_key` maps to `filesystem_tool -> SecretRead -> ssh_private_key`.
- Events that cannot match or project onto the static graph are reported as unexpected runtime-only edges.

## Writing a Fixture

A fixture is a YAML file that declares your system's components and their relationships. Here's a minimal example:

```yaml
analysis:
  max_tool_invocation_depth: 5
  max_path_length: 8

context_sources:
  - id: user_input
    source_type: user_input
    trust_level: 1

agents:
  - id: assistant
    trust_level: 2
    consumes:
      - user_input
    can_invoke:
      - search_tool

tools:
  - id: search_tool
    capabilities:
      - ExternalNetworkSend

capabilities:
  - id: ExternalNetworkSend
    severity: 3
```

See `fixtures/sample_fixture.yaml` for a full example with MCP servers, resources, and capability bindings.

### Node Types

| Type | Description | Key Attributes |
|------|-------------|----------------|
| ContextSource | Input entering an agent (user input, web content, RAG results) | `trust_level` (0-4), `source_type` |
| Agent | LLM planner or orchestrator | `trust_level` (0-4) |
| Tool | Action an agent can invoke | `mcp_server` (optional) |
| MCPServer | MCP server backing one or more tools | |
| Capability | Privileged action (shell exec, secret read, network send) | `severity` (1-4) |
| Resource | Target object (SSH key, database, repository) | `sensitivity` (1-4) |

### Trust Levels

| Level | Label | Example |
|-------|-------|---------|
| 0 | Untrusted | External webpage, unknown API response |
| 1 | Low | User input, RAG retrieval result |
| 2 | Medium | Internal agent, verified memory |
| 3 | High | Signed internal data |
| 4 | Privileged | Local filesystem, system config |

### Relationships

Edges are derived from the fixture's `consumes`, `can_invoke`, `capabilities`, `mcp_server`, and `capability_bindings` fields:

```
ContextSource -[CONSUMED_BY]-> Agent
Agent         -[CAN_INVOKE]->  Tool
Tool          -[CAN_INVOKE]->  Tool
Tool          -[EXPOSES_CAPABILITY]-> Capability
Capability    -[CAN_ACCESS_RESOURCE]-> Resource
Tool          -[USES_SERVER]-> MCPServer
```

## Detection Rules

| Rule | Triggers When |
|------|---------------|
| R001 | Low-trust context (trust <= 1) can reach a capability with severity >= 3 |
| R002 | Low-trust context can reach a resource with sensitivity >= 3 |
| R003 | A single agent can reach a dangerous capability pair (e.g. SecretRead + ExternalNetworkSend) |
| R004 | An MCP server backs critical tools invokable by more than N agents (default 3) |
| R005 | Low-trust context enters a higher-trust agent (trust >= 2) that can reach a critical capability |

### Dangerous Capability Pairs (R003)

- SecretRead + ExternalNetworkSend
- FilesystemRead + EmailSend
- ShellExecution + ExternalNetworkSend
- GitHubRead + GitHubPush
- BrowserAutomation + CredentialAccess

## Neo4j Integration

For interactive graph exploration and Cypher queries:

```bash
# Start Neo4j
docker compose up -d

# Run Neo4j integration tests
uv run pytest -m neo4j

# Run all tests (in-memory + Neo4j)
uv run pytest
```

Neo4j is available at `http://localhost:7474` (credentials: `neo4j` / `cognigraph`).

The Cypher query engine mirrors all five detection rules, so you get identical findings whether using the in-memory engine or Neo4j.

## Project Structure

```
src/cognigraph/
  schemas/        # Pydantic models: nodes, edges, enums, findings
  fixture/        # YAML fixture loading and validation
  graph/          # In-memory graph builder (NetworkX)
  rules/          # Detection rules engine
  neo4j/          # Neo4j client and Cypher detection queries
  export.py       # DOT and JSON graph export
  report.py       # CLI finding report formatter
  cli.py          # CLI entry point
fixtures/
  sample_fixture.yaml
tests/
```

## Running Tests

```bash
# Full suite (skips Neo4j tests if container is not running)
uv run pytest

# With coverage
uv run pytest --cov=cognigraph --cov-report=term-missing
```

## License

Copyright 2026 Naveen Prakaasham Vairaprakasam

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
