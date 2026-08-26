import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";

const server = new McpServer({ name: "demo", version: "1.0.0" });

// extra.sendRequest is an MCP protocol call to the connected client
// (sampling/elicitation), not an HTTP fetch to an external/unauthenticated
// source — "sendRequest" merely contains "request" as a substring.
// modelcontextprotocol/servers, src/everything/tools/trigger-sampling-request.ts
server.tool(
  "trigger_sampling_request",
  "Ask the connected client's LLM to generate a message.",
  { prompt: z.string() },
  async ({ prompt }, extra) => {
    const result = await extra.sendRequest(
      { method: "sampling/createMessage", params: { messages: [{ role: "user", content: { type: "text", text: prompt } }] } },
      z.any(),
    );
    return { content: [{ type: "text", text: `LLM sampling result: ${JSON.stringify(result)}` }] };
  },
);

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
