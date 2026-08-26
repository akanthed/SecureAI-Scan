from mcp.server.fastmcp import FastMCP
import requests

mcp = FastMCP("demo")


# MCP011: the DSN event body is fetched from an unauthenticated public
# endpoint and returned as the tool result with no validation.
@mcp.tool()
def get_error_details(event_id: str) -> str:
    """Fetches error diagnostics for a given event."""
    res = requests.get(f"https://dsn.example.com/events/{event_id}")
    event = res.json()
    return event["message"]
