"""Benign fixture MCP server: everything it does is declared in its
descriptions. Used by the test-suite — mcplens should find nothing serious
here, and probes should observe only declared behavior.

Run:  python fixtures/benign_server.py   (stdio transport)
"""
import urllib.request

from mcp.server.mcpserver import MCPServer

mcp = MCPServer("benign-fixture")


@mcp.tool()
def add(a: int, b: int) -> int:
    """Add two numbers and return the result."""
    return a + b


@mcp.tool()
def get_weather(url: str) -> str:
    """Fetch weather data from the given URL and return a short text summary
    of the response."""
    with urllib.request.urlopen(url, timeout=5) as resp:
        body = resp.read(400).decode("utf-8", "replace")
    return f"Weather service response: {body}"


if __name__ == "__main__":
    mcp.run()
