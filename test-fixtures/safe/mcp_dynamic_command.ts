import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";

// Command and args are static — nothing user-controlled reaches the transport.
export async function connectToTrustedServer() {
  const transport = new StdioClientTransport({
    command: "node",
    args: ["./trusted-mcp-server/index.js"],
  });
  const client = new Client({ name: "demo-client", version: "1.0.0" });
  await client.connect(transport);
  return client;
}
