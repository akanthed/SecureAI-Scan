# Vulnerable (MCP013): low-level Server API; os.system on a command built
# from arguments["host"] inside the call_tool dispatcher.
import os

from mcp.server import Server

server = Server("net")


@server.call_tool()
async def call_tool(name: str, arguments: dict):
    if name == "traceroute":
        host = arguments["host"]
        os.system("traceroute " + host)
        return []
    raise ValueError(name)
