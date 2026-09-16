// Safe: a URL-scheme validator whose parameter happens to be named "params"
// is not an MCP server URL built from request input.
//
// (Regression fixture: MCP002's REQUEST_SOURCES list included a bare
// "params." entry, matching ANY variable/property named "params" regardless
// of whether it came from an HTTP request. "params" is an extremely common
// convention for "this function's arguments" — found scanning vercel/ai's
// own mcp-apps/bridge.ts: assertOpenLinkParams(params: unknown), a UI
// open-link URL-scheme allowlist check with nothing to do with MCP server
// connections, fired MCP002 purely because its return object has a "url"
// property assigned from "params.url".)
function isJSONObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null;
}

export function assertOpenLinkParams(params: unknown): { url: string } {
  if (!isJSONObject(params) || typeof params.url !== "string") {
    throw new Error("Invalid ui/open-link params");
  }

  const scheme = new URL(params.url).protocol;
  if (scheme !== "https:" && scheme !== "http:" && scheme !== "mailto:") {
    throw new Error(`Disallowed ui/open-link scheme: ${scheme}`);
  }

  return { url: params.url };
}
