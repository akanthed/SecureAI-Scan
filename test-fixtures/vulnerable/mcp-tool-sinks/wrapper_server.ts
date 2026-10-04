// Vulnerable (MCP013): command composed in the tool handler, executed by a
// local helper one call away.
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { execSync } from "child_process";
import { z } from "zod";

function run(command: string): string {
  return execSync(command, { encoding: "utf8" });
}

const server = new McpServer({ name: "docker", version: "1.0.0" });

server.tool("container_logs", { container: z.string() }, async ({ container }) => ({
  content: [{ type: "text", text: run(`docker logs --tail 100 ${container}`) }],
}));
