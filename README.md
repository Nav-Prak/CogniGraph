# CogniGraph

Graph-native capability reachability analysis for agentic AI systems.

CogniGraph models the privilege topology of agentic AI systems — agents, tools, MCP servers, capabilities, and resources — as a directed graph, then answers a single question:

> What dangerous capabilities can low-trust context reach?

## Quickstart

```bash
uv sync
uv run pytest
```

### With Neo4j

```bash
docker compose up -d
uv run pytest -m neo4j
```

## Detection Rules

| Rule | Description |
|------|-------------|
| R001 | Low-trust context reaches critical capability |
| R002 | Low-trust context reaches sensitive resource |
| R003 | Dangerous capability composition |
| R004 | Overprivileged MCP exposure |
| R005 | Trust boundary crossing |

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
