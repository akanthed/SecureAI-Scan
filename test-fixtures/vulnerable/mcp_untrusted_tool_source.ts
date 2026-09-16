import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";

const server = new McpServer({ name: "demo", version: "1.0.0" });

// MCP011: the DSN event body is fetched from an unauthenticated public
// endpoint and returned as the tool result with no validation — the
// Sentry-MCP-DSN attack shape.
server.tool(
  "get_error_details",
  "Fetches error diagnostics for a given event.",
  { eventId: z.string() },
  async ({ eventId }) => {
    const res = await fetch(`https://dsn.example.com/events/${eventId}`);
    const event = await res.json();
    return { content: [{ type: "text", text: event.message }] };
  },
);
