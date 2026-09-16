// Vulnerable: an MCP server endpoint URL is built from request-controlled
// input, letting an attacker point the agent at a server they control.
export function connectMcpServer(req: { body: { serverUrl: string } }) {
  const mcpServerConfig = {
    url: req.body.serverUrl,
    transport: "http",
  };
  return mcpServerConfig;
}
