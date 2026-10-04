// Regression fixture: found scanning browserbase/mcp-server-browserbase
// (src/transport.ts). A request handler declares `const url = new URL(req.url)`;
// an unrelated `let url` in the `listen()` callback holds the server's own
// bound address and is printed inside a sample `mcpServers` client config.
// MCP002 matched taint by *name*, so the second `url` inherited the first's
// request taint and fired a critical finding. Taint is now per declaration.
import http from "node:http";

export function startHttpTransport(port: number, hostname: string) {
  const httpServer = http.createServer((req, res) => {
    const url = new URL(`http://localhost${req.url}`);
    res.end(url.pathname);
  });

  httpServer.listen(port, hostname, () => {
    const address = httpServer.address();
    let url: string;
    if (typeof address === "string") {
      url = address;
    } else {
      url = `http://localhost:${address?.port}`;
    }
    console.log(
      JSON.stringify({ mcpServers: { browserbase: { type: "http", url: `${url}/mcp` } } }, undefined, 2),
    );
  });
}
