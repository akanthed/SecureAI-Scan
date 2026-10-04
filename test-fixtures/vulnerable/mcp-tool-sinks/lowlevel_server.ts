// Vulnerable (MCP013 + MCP014): low-level Server API dispatching on
// request.params.name, with arguments read from request.params.arguments.
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { CallToolRequestSchema } from "@modelcontextprotocol/sdk/types.js";
import * as cp from "child_process";
import fs from "fs/promises";
import path from "path";

const WORKSPACE = "/srv/workspace";
const server = new Server({ name: "ops", version: "1.0.0" }, { capabilities: { tools: {} } });

server.setRequestHandler(CallToolRequestSchema, async (request) => {
  const { name, arguments: args } = request.params;
  if (name === "ping_host") {
    const host = String(args?.host);
    const out = cp.execSync("ping -c 1 " + host).toString();
    return { content: [{ type: "text", text: out }] };
  }
  if (name === "read_doc") {
    const file = path.join(WORKSPACE, args?.file as string);
    return { content: [{ type: "text", text: await fs.readFile(file, "utf8") }] };
  }
  throw new Error("unknown tool");
});
