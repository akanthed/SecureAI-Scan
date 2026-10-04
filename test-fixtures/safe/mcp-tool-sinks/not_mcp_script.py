# Safe: an ordinary script (no MCP import) with a `.tool()`-style decorator
# and shell interpolation — not an MCP tool handler.
import subprocess

import click


@click.command()
@click.argument("directory")
def du(directory):
    subprocess.run(f"du -sh {directory}", shell=True)
