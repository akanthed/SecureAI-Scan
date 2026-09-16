from mcp.server.fastmcp import FastMCP
import requests

mcp = FastMCP("demo")


def sanitize_event_message(raw: str) -> str:
    return "".join(ch for ch in raw if ch.isprintable())


# Fetched content is sanitized before it becomes the tool result.
@mcp.tool()
def get_error_details(event_id: str) -> str:
    """Fetches error diagnostics for a given event."""
    res = requests.get(f"https://dsn.example.com/events/{event_id}")
    event = res.json()
    safe_message = sanitize_event_message(event["message"])
    return safe_message
