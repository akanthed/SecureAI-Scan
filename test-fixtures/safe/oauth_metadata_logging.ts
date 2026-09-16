// Regression fixture: "token" compounds that name metadata about a token
// (a URL, a type) are not the token value itself — found via real-world
// scan of the MCP TypeScript SDK (examples/guides/advanced/wire-schemas).
export async function logOAuthDiscovery(response: Response) {
  const metadata = await response.json();
  console.log(metadata.token_endpoint);
  console.log(metadata.tokenType);
  console.log(metadata.token_endpoint_auth_method);
}
