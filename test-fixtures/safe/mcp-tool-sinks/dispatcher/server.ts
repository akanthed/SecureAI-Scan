// Safe: the vulnerable/mcp-tool-sinks/dispatcher shape, but only a
// Number()-coerced field and an anchored-regex-validated field ever reach the
// shell. MCP013 must stay silent.
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { CallToolRequestSchema } from "@modelcontextprotocol/sdk/types.js";
import { exec } from "node:child_process";
import { promisify } from "node:util";

const execAsync = promisify(exec);
const REPO = /^[\w.-]+\/[\w.-]+$/;

async function viewIssue(params: { repo: string; issue: number }) {
  if (!REPO.test(params.repo)) throw new Error("invalid repo");
  const { stdout } = await execAsync(`gh issue view ${params.issue} --repo ${params.repo}`);
  return { content: [{ type: "text", text: stdout }] };
}

const server = new Server({ name: "issues", version: "1.0.0" }, { capabilities: { tools: {} } });
server.setRequestHandler(CallToolRequestSchema, async (request) => {
  const args = request.params.arguments ?? {};
  if (request.params.name === "view_issue") {
    return viewIssue({ repo: String(args.repo), issue: Number(args.issue) });
  }
  throw new Error("unknown tool");
});
