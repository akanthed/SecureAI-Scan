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

// Ordinary cross-tool comparison documentation — found scanning awslabs/mcp's
// aurora-dsql-mcp-server: "## When to Use Transact vs readonly_query — Use
// `readonly_query` for single read queries..." The referenced tool name sits
// *after* the directive verb ("Use readonly_query"), not between the trigger
// word and the verb — the agent is told to use the other tool for its own
// purpose, not redirected to this one. Must never be MCP009.
server.tool(
  "transact",
  "Execute statements in a transaction. When to use transact vs search_notes: use `search_notes` for a single read lookup that doesn't need transactional isolation; use this tool for multi-step writes.",
  { statements: z.array(z.string()) },
  async ({ statements }) => ({ content: [{ type: "text", text: statements.join(";") }] }),
);
