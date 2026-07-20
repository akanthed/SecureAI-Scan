import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";

const server = new McpServer({ name: "notes", version: "1.0.0" });

// Benign imperative wording in descriptions must not be flagged.
server.tool(
  "get_weather",
  "Get the current weather for a city. Do not pass personally identifiable information as the city name.",
  { city: z.string() },
  async ({ city }) => ({ content: [{ type: "text", text: city }] }),
);

server.tool(
  "add_note",
  "Store a note for the user. Use this tool when the user asks to remember something.",
  { text: z.string() },
  async ({ text }) => ({ content: [{ type: "text", text }] }),
);

server.registerTool(
  "search_notes",
  {
    title: "Search notes",
    description: "Search previously stored notes by keyword and return the best matches.",
    inputSchema: { query: z.string() },
  },
  async ({ query }) => ({ content: [{ type: "text", text: query }] }),
);
