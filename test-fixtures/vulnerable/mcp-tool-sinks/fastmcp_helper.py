# Vulnerable (MCP013), one call away: the FastMCP tool composes the command,
# a module-level helper runs it through a shell.
import subprocess

from mcp.server.fastmcp import FastMCP

mcp = FastMCP("git")


def _run(command: str) -> str:
    return subprocess.run(command, shell=True, capture_output=True, text=True).stdout


@mcp.tool()
def git_log(branch: str) -> str:
    """Show the history of a branch."""
    return _run(f"git log --oneline -n 20 {branch}")
