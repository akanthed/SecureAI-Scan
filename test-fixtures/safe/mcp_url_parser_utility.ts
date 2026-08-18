// Safe: found scanning BerriAI/litellm's ui/litellm-dashboard/src/app/(dashboard)/mcp-servers/_components/utils.tsx.
// A pure URL-parsing utility whose parameter happens to be named "url" is
// not "user-controlled input" in the request-taint sense MCP002 targets —
// nothing here proves the parameter came from an HTTP request rather than,
// say, a hardcoded config value passed by the caller.
export const extractMCPToken = (url: string): { token: string | null; baseUrl: string } => {
  const mcpIndex = url.indexOf("/mcp/");
  if (mcpIndex === -1) return { token: null, baseUrl: url };

  const parts = url.split("/mcp/");
  if (parts.length !== 2) return { token: null, baseUrl: url };

  const afterMcp = parts[1];
  if (!afterMcp) return { token: null, baseUrl: url };

  return { token: afterMcp, baseUrl: parts[0] + "/mcp/" };
};
