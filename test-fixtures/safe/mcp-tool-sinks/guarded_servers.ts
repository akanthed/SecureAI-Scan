// Safe: the same tool shapes as vulnerable/mcp-tool-sinks/, each with the
// fix applied. MCP013/MCP014 must stay silent on every one.
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { exec, execFile, execFileSync, execSync, spawn } from "node:child_process";
import { readFile, realpath } from "node:fs/promises";
import path from "node:path";
import { z } from "zod";

const ROOT = "/srv/workspace";
const BRANCH = /^[\w./-]+$/;
const ALLOWED_SERVICES = ["web", "worker"];
const server = new McpServer({ name: "safe", version: "1.0.0" });

// Argument array, no shell: metacharacters are inert.
server.tool("git_log", { branch: z.string() }, async ({ branch }) => ({
  content: [{ type: "text", text: execFileSync("git", ["log", "--oneline", branch]).toString() }],
}));

// Regex-guarded before interpolation.
server.tool("git_show", { ref: z.string() }, async ({ ref }) => {
  if (!BRANCH.test(ref)) throw new Error("bad ref");
  return { content: [{ type: "text", text: execSync(`git show ${ref}`).toString() }] };
});

// Schema restricts the value to an enum / a number.
server.tool("restart", { service: z.enum(["web", "worker"]) }, async ({ service }) => {
  exec(`systemctl restart ${service}`);
  return { content: [{ type: "text", text: "ok" }] };
});
server.tool("kill", { pid: z.number().int() }, async ({ pid }) => {
  exec(`kill -9 ${pid}`);
  return { content: [{ type: "text", text: "ok" }] };
});

// Allowlist check.
server.tool("logs", { svc: z.string() }, async ({ svc }) => {
  if (!ALLOWED_SERVICES.includes(svc)) throw new Error("unknown service");
  return { content: [{ type: "text", text: execSync(`journalctl -u ${svc}`).toString() }] };
});

// spawn without shell: true is an argument vector.
server.tool("grep", { pattern: z.string() }, async ({ pattern }) => {
  spawn("grep", ["-rn", pattern, ROOT]);
  execFile("rg", [pattern]);
  return { content: [{ type: "text", text: "started" }] };
});

// Containment check after joining.
server.tool("read_doc", { file: z.string() }, async ({ file }) => {
  const target = await realpath(path.resolve(ROOT, file));
  if (!target.startsWith(ROOT + path.sep)) throw new Error("outside workspace");
  return { content: [{ type: "text", text: await readFile(target, "utf8") }] };
});

// Containment enforced by a named validation helper.
async function validatePath(p: string): Promise<string> {
  const resolved = path.resolve(p);
  if (!resolved.startsWith(ROOT)) throw new Error("denied");
  return resolved;
}
server.tool("read_file", { file: z.string() }, async ({ file }) => {
  const safe = await validatePath(path.join(ROOT, file));
  return { content: [{ type: "text", text: await readFile(safe, "utf8") }] };
});

// Fixed command with no tool data at all.
server.tool("status", {}, async () => ({
  content: [{ type: "text", text: execSync("git status --short").toString() }],
}));
