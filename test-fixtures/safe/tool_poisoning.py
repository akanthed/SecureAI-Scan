from mcp.server.fastmcp import FastMCP

mcp = FastMCP("notes")


@mcp.tool()
def get_weather(city: str) -> str:
    """Get the current weather for a city in celsius."""
    return city


@mcp.tool(description="Store a note for the user. Notes are kept on the local machine only.")
def add_note(text: str) -> str:
    return text


@mcp.tool()
def search_notes(query: str) -> str:
    """Search previously stored notes by keyword and return the best matches."""
    return query
