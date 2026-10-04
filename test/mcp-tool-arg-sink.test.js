import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { scanRepositoryDetailed } from "../dist/scanner/scan.js";

/**
 * MCP013/MCP014 precision contract (see src/scanner/rules/mcp-tool-arg-sink.ts):
 * default evidence only when a tool argument is composed into a fixed command
 * or joined onto a base directory with no guard; by-design "run anything" /
 * "read anything" tools are heuristic-only; any guard silences the rule.
 */

const here = path.dirname(fileURLToPath(import.meta.url));
const fixtures = path.resolve(here, "..", "test-fixtures");
const ids = new Set(["MCP013", "MCP014"]);

function scan(dir) {
  return scanRepositoryDetailed(dir).findings.filter((f) => ids.has(f.rule_id));
}

function tempRepo(files) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "secureai-mcp-sink-"));
  for (const [name, content] of Object.entries(files)) {
    fs.mkdirSync(path.dirname(path.join(dir, name)), { recursive: true });
    fs.writeFileSync(path.join(dir, name), content);
  }
  return dir;
}

test("safe MCP tool handlers produce no MCP013/MCP014 at any evidence tier", () => {
  const hits = scan(path.join(fixtures, "safe", "mcp-tool-sinks"));
  assert.deepEqual(hits.map((f) => `${f.rule_id} ${f.file}:${f.line} [${f.evidence}]`), []);
});

test("a command composed from a tool argument is proven, with a source→sink trace", () => {
  const hits = scan(path.join(fixtures, "vulnerable", "mcp-tool-sinks"));
  const git = hits.find((f) => f.rule_id === "MCP013" && f.file.endsWith("git_server.ts"));
  assert.ok(git, "git_server.ts should fire MCP013");
  assert.equal(git.evidence, "proven");
  assert.equal(git.severity, "critical");
  assert.deepEqual(git.trace.map((step) => step.kind), ["source", "sink"]);
  assert.match(git.trace[0].note, /tool argument `branch` of MCP tool `git_log`/);
  const lowLevel = hits.find((f) => f.rule_id === "MCP014" && f.file.endsWith("lowlevel_server.ts"));
  assert.match(lowLevel.summary, /`read_doc`/, "low-level dispatch should name the tool");
});

test("a bare run-anything / read-anything tool is heuristic only", () => {
  const dir = tempRepo({
    "server.ts": [
      'import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";',
      'import { execSync } from "node:child_process";',
      'import { readFileSync } from "node:fs";',
      'import { z } from "zod";',
      'const server = new McpServer({ name: "shell", version: "1.0.0" });',
      'server.tool("run", { command: z.string() }, async ({ command }) => ({ content: [{ type: "text", text: execSync(command).toString() }] }));',
      'server.tool("cat", { file: z.string() }, async ({ file }) => ({ content: [{ type: "text", text: readFileSync(file, "utf8") }] }));',
      "",
    ].join("\n"),
    "tools.py": [
      "import subprocess",
      "from mcp.server.fastmcp import FastMCP",
      'mcp = FastMCP("shell")',
      "@mcp.tool()",
      "def run(command: str) -> str:",
      "    return subprocess.run(command, shell=True, capture_output=True, text=True).stdout",
      "",
    ].join("\n"),
  });
  try {
    const hits = scan(dir);
    assert.equal(hits.length, 3);
    assert.ok(hits.every((f) => f.evidence === "heuristic" && f.severity === "medium"), JSON.stringify(hits.map((f) => [f.file, f.evidence])));
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test("MCP013 demotes in test/example paths", () => {
  const dir = tempRepo({
    "examples/server.ts": fs.readFileSync(path.join(fixtures, "vulnerable", "mcp-tool-sinks", "git_server.ts"), "utf8"),
  });
  try {
    const hits = scan(dir);
    assert.equal(hits.length, 1);
    assert.equal(hits[0].evidence, "likely");
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test("taint follows imports through tsconfig path aliases (@/lib/...)", () => {
  const dir = tempRepo({
    "tsconfig.json": '{\n  // comments are allowed\n  "compilerOptions": { "baseUrl": ".", "paths": { "@/*": ["./src/*"] } }\n}\n',
    "src/lib/shell.ts": [
      'import { execSync } from "node:child_process";',
      "export function run(command: string): string {",
      "  return execSync(command).toString();",
      "}",
      "",
    ].join("\n"),
    "src/server.ts": [
      'import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";',
      'import { z } from "zod";',
      'import { run } from "@/lib/shell";',
      'const server = new McpServer({ name: "git", version: "1.0.0" });',
      'server.tool("git_log", { branch: z.string() }, async ({ branch }) => ({',
      '  content: [{ type: "text", text: run(`git log ${branch}`) }],',
      "}));",
      "",
    ].join("\n"),
  });
  try {
    const hits = scan(dir);
    assert.equal(hits.length, 1, JSON.stringify(hits));
    assert.equal(hits[0].file.replace(/\\/g, "/"), "src/lib/shell.ts");
    assert.equal(hits[0].evidence, "likely");
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test("a reused command variable is judged by the value that reaches each exec (found in mcp-server-kubernetes)", () => {
  const dir = tempRepo({
    "context.ts": [
      'import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";',
      'import { execSync } from "node:child_process";',
      'import { z } from "zod";',
      "function addOptions(command: string, input: { tail?: number }) {",
      "  return input.tail ? `${command} --tail=${input.tail}` : command;",
      "}",
      'const server = new McpServer({ name: "k8s", version: "1.0.0" });',
      'server.tool("context", { op: z.string(), name: z.string(), tail: z.number().optional() }, async (input) => {',
      '  let command = "";',
      "  switch (input.op) {",
      '    case "list":',
      '      command = "kubectl config get-contexts";', // static: must not fire
      "      return execSync(command).toString();",
      '    case "use":',
      "      command = `kubectl config use-context ${input.name}`;",
      "      return execSync(command).toString();",
      "    default:",
      "      command = `kubectl logs ${input.name}`;",
      "      command = addOptions(command, input);", // passes the value through
      "      return execSync(command).toString();",
      "  }",
      "});",
      "",
    ].join("\n"),
  });
  try {
    const lines = scan(dir).filter((f) => f.rule_id === "MCP013").map((f) => f.line).sort((a, b) => a - b);
    // The "use" exec and the default-branch exec; never the static "list" one.
    assert.deepEqual(lines, [16, 20]);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});
