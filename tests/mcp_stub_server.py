"""Minimal stdio MCP server used by the introspection integration tests.

Tool docstrings deliberately contain keywords the heuristic capability
mapper recognizes ("read file", "send email"), so the collect --introspect
--> --infer-capabilities pipeline can be exercised end to end.
"""

from mcp.server.fastmcp import FastMCP

server = FastMCP("cognigraph-stub")


@server.tool()
def read_file(path: str) -> str:
    """Read file contents from the local filesystem."""
    return ""


@server.tool()
def send_email(to: str, body: str) -> str:
    """Send email to a recipient."""
    return ""


if __name__ == "__main__":
    server.run()
