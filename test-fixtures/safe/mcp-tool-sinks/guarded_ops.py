# Safe: the vulnerable/mcp-tool-sinks/ Python shapes with the fix applied.
# MCP013/MCP014 must stay silent on every one.
import re
import shlex
import subprocess
from pathlib import Path
from typing import Literal

from mcp.server.fastmcp import FastMCP

mcp = FastMCP("ops")
REPORTS = Path("/srv/reports")
SAFE = re.compile(r"^[\w./-]+$")


@mcp.tool()
def disk_usage(directory: str) -> str:
    """Argument list, no shell."""
    return subprocess.run(["du", "-sh", directory], capture_output=True, text=True).stdout


@mcp.tool()
def quoted(directory: str) -> str:
    """Quoted with shlex."""
    return subprocess.run(f"du -sh {shlex.quote(directory)}", shell=True, capture_output=True, text=True).stdout


@mcp.tool()
def validated(directory: str) -> str:
    """Regex-validated before use."""
    if not SAFE.fullmatch(directory):
        raise ValueError("bad path")
    return subprocess.run(f"du -sh {directory}", shell=True, capture_output=True, text=True).stdout


@mcp.tool()
def restart(service: Literal["web", "worker"]) -> str:
    """Literal-typed argument."""
    return subprocess.run(f"systemctl restart {service}", shell=True, capture_output=True, text=True).stdout


@mcp.tool()
def tail(lines: int) -> str:
    """Integer argument."""
    return subprocess.run(f"tail -n {lines} /var/log/app.log", shell=True, capture_output=True, text=True).stdout


@mcp.tool()
def read_report(name: str) -> str:
    """Containment-checked path."""
    target = (REPORTS / name).resolve()
    if not target.is_relative_to(REPORTS.resolve()):
        raise ValueError("outside reports")
    return target.read_text()


@mcp.tool()
def allowlisted(name: str) -> str:
    """Allowlisted file name."""
    if name not in {"daily.txt", "weekly.txt"}:
        raise ValueError("unknown report")
    return (REPORTS / name).read_text()
