# Safe: the vulnerable/mcp-tool-sinks/fastmcp_helper.py shape with each fix:
# a validated argument, a quoted argument, and an int-typed argument reaching
# the same shell helper. MCP013 must stay silent.
import re
import shlex
import subprocess

from mcp.server.fastmcp import FastMCP

mcp = FastMCP("git")
REF = re.compile(r"^[\w./-]+$")


def _run(command: str) -> str:
    return subprocess.run(command, shell=True, capture_output=True, text=True).stdout


@mcp.tool()
def git_log(branch: str) -> str:
    """Validated before use."""
    if not REF.fullmatch(branch):
        raise ValueError("invalid branch")
    return _run(f"git log --oneline -n 20 {branch}")


@mcp.tool()
def git_show(ref: str) -> str:
    """Quoted for the shell."""
    return _run(f"git show {shlex.quote(ref)}")


@mcp.tool()
def git_recent(count: int) -> str:
    """An int can't carry a shell metacharacter."""
    return _run(f"git log -n {count}")
