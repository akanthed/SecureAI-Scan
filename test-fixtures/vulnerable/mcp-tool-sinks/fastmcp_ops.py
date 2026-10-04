# Vulnerable (MCP013 + MCP014): FastMCP tools composing a shell command and
# joining a path under a base directory, with no guard on either.
import os
import subprocess
from pathlib import Path

from mcp.server.fastmcp import FastMCP

mcp = FastMCP("ops")
REPORTS = Path("/srv/reports")


@mcp.tool()
def disk_usage(directory: str) -> str:
    """Show disk usage for a directory."""
    return subprocess.run(f"du -sh {directory}", shell=True, capture_output=True, text=True).stdout


@mcp.tool()
def read_report(name: str) -> str:
    """Read a generated report."""
    return (REPORTS / name).read_text()
