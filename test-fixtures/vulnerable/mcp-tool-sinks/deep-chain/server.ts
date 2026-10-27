// Vulnerable (MCP013), five calls deep: tool handler -> a -> b -> c -> d -> exec.
// Found by the corpus mutations (corpus/): the Figma-Context-MCP CVE already
// used four hops, so one harmless extra wrapper put the sink out of reach.
import { exec } from "child_process";
import { promisify } from "util";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";

const execAsync = promisify(exec);

async function stepA(target: string) {
  return stepB(target);
}
async function stepB(target: string) {
  return stepC(target);
}
async function stepC(target: string) {
  return stepD(target);
}
async function stepD(target: string) {
  return stepE(`curl -s -L "${target}"`);
}
async function stepE(command: string) {
  const { stdout } = await execAsync(command);
  return stdout;
}

const server = new McpServer({ name: "fetcher", version: "1.0.0" });
server.tool("fetch_url", { url: z.string() }, async ({ url }) => ({
  content: [{ type: "text", text: await stepA(url) }],
}));
