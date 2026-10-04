// Vulnerable (MCP013): high-level McpServer API; tool argument interpolated
// into a shell command through a promisified exec.
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { exec } from "node:child_process";
import { promisify } from "node:util";
import { z } from "zod";

const execAsync = promisify(exec);
const server = new McpServer({ name: "git-helper", version: "1.0.0" });

server.tool("git_log", "Show history for a branch", { branch: z.string() }, async ({ branch }) => {
  const { stdout } = await execAsync(`git log --oneline -n 20 ${branch}`);
  return { content: [{ type: "text", text: stdout }] };
});
