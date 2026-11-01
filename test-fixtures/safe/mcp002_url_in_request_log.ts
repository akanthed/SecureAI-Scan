// Safe: regression from czlonkowski/n8n-mcp (an MCP server's own HTTP handler).
// `url: req.url` is a field of a log record; the object is passed to a logger,
// not used as an MCP server or client configuration. MCP002 treated any file
// that mentions "mcp" near a request-derived `url` property as a dynamic MCP
// server URL.
declare const logger: { info(message: string, meta: Record<string, unknown>): void };

export function handleMcpRequest(req: { method: string; url: string }) {
  logger.info("MCP request received", {
    method: req.method,
    url: req.url,
  });
}
