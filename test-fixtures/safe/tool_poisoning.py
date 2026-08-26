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


# Ordinary workflow-prerequisite documentation — found scanning awslabs/mcp's
# dynamodb-mcp-server: "PREREQUISITE: Before calling this tool, you MUST
# first call `dynamodb_data_model_schema_converter` to generate schema.json."
# The referenced tool is the *object* of "call", after the verb, not the
# subject of the trigger clause — this documents a genuine two-step workflow
# between sibling tools the same author owns, not tool-shadowing. Must never
# be MCP009.
@mcp.tool()
def export_notes(format: str) -> str:
    """Export stored notes to a file.

    PREREQUISITE: Before calling this tool, you must first call `search_notes`
    to confirm there is at least one note to export.
    """
    return format
