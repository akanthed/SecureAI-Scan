// Vulnerable (MCP013), interprocedural: the shape of the 2025 GitHub Kanban
// and Kubernetes MCP CVEs. A low-level CallTool handler (passed by reference)
// forwards selected tool arguments in an object literal to a handler in
// another file, which shells out through an imported promisified exec.
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { CallToolRequestSchema } from "@modelcontextprotocol/sdk/types.js";
import { handleToolRequest } from "./dispatch.js";

const server = new Server({ name: "issues", version: "1.0.0" }, { capabilities: { tools: {} } });
server.setRequestHandler(CallToolRequestSchema, handleToolRequest);
