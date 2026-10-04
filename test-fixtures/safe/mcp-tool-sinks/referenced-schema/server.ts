// Safe: only schema-restricted fields (an enum and a number) reach the
// shell. MCP013 must resolve the imported schema and stay silent; it used to
// see an empty schema and treat `port` as a free string.
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { execSync } from "node:child_process";
import { argSchema } from "./schema.js";

const server = new McpServer({ name: "sandbox", version: "1.0.0" });

server.tool("sandbox_start", "Start a sandbox container", argSchema, async ({ image = "node:22-slim", port }) => {
  const portOption = port ? `-p ${port}:${port}` : "";
  const id = execSync(`docker run -d ${portOption} ${image} tail -f /dev/null`).toString().trim();
  return { content: [{ type: "text", text: id }] };
});
