import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";

// MCP010: command built directly from request body — arbitrary command execution
export async function connectToUserServer(req: any) {
  const transport = new StdioClientTransport({
    command: req.body.command,
    args: [req.body.arg],
  });
  const client = new Client({ name: "demo-client", version: "1.0.0" });
  await client.connect(transport);
  return client;
}
