// Safe: the same five-call chain as vulnerable/mcp-tool-sinks/deep-chain, but
// the value is checked against an allowlist of hosts midway, so no finding at
// any evidence tier. Pins that the deeper hop budget did not loosen guards.
import { exec } from "child_process";
import { promisify } from "util";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";

const execAsync = promisify(exec);
const ALLOWED_HOSTS = new Set(["api.example.com", "docs.example.com"]);

async function stepA(host: string) {
  return stepB(host);
}
async function stepB(host: string) {
  if (!ALLOWED_HOSTS.has(host)) throw new Error("host not allowed");
  return stepC(host);
}
async function stepC(host: string) {
  return stepD(host);
}
async function stepD(host: string) {
  return stepE(`curl -s -L "https://${host}/status"`);
}
async function stepE(command: string) {
  const { stdout } = await execAsync(command);
  return stdout;
}

const server = new McpServer({ name: "fetcher", version: "1.0.0" });
server.tool("fetch_status", { host: z.string() }, async ({ host }) => ({
  content: [{ type: "text", text: await stepA(host) }],
}));
