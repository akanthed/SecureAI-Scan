// Vulnerable (MCP014): registerTool with inputSchema; template-joined path
// under a base directory with no containment check.
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { writeFileSync } from "node:fs";
import { z } from "zod";

const NOTES_DIR = "/home/app/notes";
const server = new McpServer({ name: "notes", version: "1.0.0" });

server.registerTool(
  "save_note",
  { description: "Save a note", inputSchema: { title: z.string(), body: z.string() } },
  async ({ title, body }) => {
    writeFileSync(`${NOTES_DIR}/${title}.md`, body);
    return { content: [{ type: "text", text: "saved" }] };
  },
);
