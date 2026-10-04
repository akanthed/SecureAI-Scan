// Vulnerable (MCP013), interprocedural: the shape of the Figma and
// package-docs MCP CVEs. A tool registry object supplies the name and a
// handler reference; the argument flows through class methods and a
// conditional command string into exec several calls away.
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { DocsService } from "./docs-service.js";

const docs = new DocsService();
const lookupDocTool = {
  name: "lookup_go_doc",
  parameters: { package: z.string(), symbol: z.string().optional() },
  handler: lookupDoc,
};

async function lookupDoc(params: { package: string; symbol?: string }, service: DocsService) {
  const { package: pkg, symbol } = params;
  return { content: [{ type: "text", text: await service.describe(pkg, symbol) }] };
}

const server = new McpServer({ name: "docs", version: "1.0.0" });
server.tool(lookupDocTool.name, lookupDocTool.parameters, (params) => lookupDocTool.handler(params, docs));
