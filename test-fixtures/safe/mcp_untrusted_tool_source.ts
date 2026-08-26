import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";

const server = new McpServer({ name: "demo", version: "1.0.0" });

function sanitizeEventMessage(raw: string): string {
  return raw.replace(/[^\x20-\x7e]/g, "");
}

// Fetched content is sanitized before it becomes the tool result.
server.tool(
  "get_error_details",
  "Fetches error diagnostics for a given event.",
  { eventId: z.string() },
  async ({ eventId }) => {
    const res = await fetch(`https://dsn.example.com/events/${eventId}`);
    const event = await res.json();
    const safeMessage = sanitizeEventMessage(event.message);
    return { content: [{ type: "text", text: safeMessage }] };
  },
);
