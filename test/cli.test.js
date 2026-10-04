import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { execFileSync } from "node:child_process";
import { fileURLToPath } from "node:url";

/**
 * CLI-level smoke tests. Every other test file calls the scanner functions
 * directly, bypassing src/cli.ts entirely — so a bug in flag wiring (a
 * dropped parser argument, a flag that silently no-ops) has no test that
 * would catch it. This file exercises the built binary the way a user
 * actually invokes it.
 */

const here = path.dirname(fileURLToPath(import.meta.url));
const cliPath = path.resolve(here, "..", "dist", "index.js");

function run(args, options = {}) {
  try {
    const stdout = execFileSync("node", [cliPath, ...args], { encoding: "utf-8", ...options });
    return { stdout, status: 0 };
  } catch (err) {
    return { stdout: err.stdout?.toString() ?? "", stderr: err.stderr?.toString() ?? "", status: err.status };
  }
}

test("scan on a nonexistent path errors loudly instead of silently reporting 0 findings", () => {
  const { stdout, stderr, status } = run(["scan", "/definitely/does/not/exist/xyz"]);
  assert.equal(status, 1);
  assert.match(stderr, /does not exist/);
  assert.equal(stdout, "", "expected no report output for a path that was never scanned");
});

test("scan -r <RULE_ID> actually filters to that rule (not silently ignored)", () => {
  const { stdout, status } = run(["scan", "test-fixtures/vulnerable", "-r", "AI001", "--limit", "20"]);
  assert.equal(status, 0);
  assert.match(stdout, /AI001/);
  assert.doesNotMatch(stdout, /\bAI005\b/, "expected AI005 to be filtered out by -r AI001");
});

test("scan --only-skl scopes to SKL rules only", () => {
  const { stdout, status } = run(["scan", "test-fixtures/vulnerable/skills", "--only-skl", "--limit", "20"]);
  assert.equal(status, 0);
  assert.match(stdout, /SKL00/);
  assert.doesNotMatch(stdout, /\b(?:AI|MCP|VEC|DEP)\d{3}\b/, "expected only SKL rule IDs to appear");
});

test("scan --only-mcp scopes to MCP rules only", () => {
  const { stdout, status } = run(["scan", "test-fixtures/vulnerable", "--only-mcp", "--limit", "20"]);
  assert.equal(status, 0);
  assert.match(stdout, /MCP00/);
  assert.doesNotMatch(stdout, /\b(?:AI|SKL|VEC|DEP)\d{3}\b/, "expected only MCP rule IDs to appear");
});

test("skill <local-path> scans a fetched target without cloning (local path shortcut)", () => {
  const { stdout, status } = run(["skill", "test-fixtures/vulnerable/skills/leaky-skill", "--limit", "20"]);
  assert.equal(status, 0);
  assert.match(stdout, /SKL00/);
});

test("skill <path-with-no-SKILL.md> reports nothing to scan instead of a silent empty report", () => {
  const { stdout, status } = run(["skill", "test-fixtures/safe/env_config.py", "--limit", "20"]);
  assert.equal(status, 0);
  assert.match(stdout, /No SKILL\.md found/);
});

test("mcp <local-path> runs the full rule set plus DEP003 advisories", () => {
  const { stdout, status } = run(["mcp", "test-fixtures/vulnerable", "--limit", "40"]);
  assert.equal(status, 0);
  assert.match(stdout, /MCP00/);
});

test("skill/mcp --fail-on actually exits non-zero when findings meet the threshold", () => {
  const { status } = run(["skill", "test-fixtures/vulnerable/skills/leaky-skill", "--fail-on", "critical"]);
  assert.equal(status, 1);
});

test("scan --only-mcp and --only-skl combine to scope both categories", () => {
  const { stdout, status } = run(["scan", "test-fixtures/vulnerable", "--only-mcp", "--only-skl", "--limit", "40"]);
  assert.equal(status, 0);
  assert.match(stdout, /MCP00/);
  assert.match(stdout, /SKL00/);
  assert.doesNotMatch(stdout, /\b(?:AI|VEC|DEP)\d{3}\b/, "expected AI/VEC/DEP rule IDs to be filtered out");
});

test("scan -r DEP001 auto-enables the registry check it depends on (no separate --check-dependencies needed)", () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "secureai-cli-dep-"));
  fs.writeFileSync(
    path.join(dir, "package.json"),
    JSON.stringify({ name: "tmp", version: "1.0.0", dependencies: { "hallucinated-pkg-cli-test": "1.0.0" } }),
  );
  const { stdout, status } = run(["scan", dir, "-r", "DEP001"]);
  assert.equal(status, 0);
  assert.match(stdout, /DEP001/, "DEP001 must fire without a separate --check-dependencies flag");
});

test("scan rejects an invalid --severity value with a clean error, not a stack trace", () => {
  const { stderr, status } = run(["scan", "test-fixtures/vulnerable", "--severity", "nonsense"]);
  assert.notEqual(status, 0);
  assert.match(stderr, /Invalid severity/i);
  assert.doesNotMatch(stderr, /at Command\.|at Object\./, "should not leak a raw stack trace for a user input error");
});

test("scan rejects an unknown rule ID with a clean error", () => {
  const { stderr, status } = run(["scan", "test-fixtures/vulnerable", "-r", "NOT_A_REAL_RULE"]);
  assert.notEqual(status, 0);
  assert.match(stderr, /Unknown rule ID/i);
});

test("scan -r SKL004 reaches the new bundle rules through the CLI", () => {
  // The bundle rules run outside the AST engine, so a wiring regression in
  // SKILL_RULE_IDS would silently drop them from -r/--only-skl with every
  // other test still green.
  const { stdout, status } = run(["scan", "test-fixtures/vulnerable/skills", "-r", "SKL004", "--limit", "20"]);
  assert.equal(status, 0);
  assert.match(stdout, /SKL004/);
  assert.doesNotMatch(stdout, /SKL001|SKL002|SKL003|SKL005/);
});

test("scan -r SKL005 reports the payload staged in a test file", () => {
  const { stdout, status } = run(["scan", "test-fixtures/vulnerable/skills", "-r", "SKL005", "--limit", "20"]);
  assert.equal(status, 0);
  assert.match(stdout, /SKL005/);
  assert.match(stdout, /metrics\.test\.ts/);
});

test("scan -r MCP013 and --only-mcp reach the tool-argument sink rules through the CLI", () => {
  const out = path.join(fs.mkdtempSync(path.join(os.tmpdir(), "secureai-cli-mcp013-")), "report.json");
  for (const scope of [["-r", "MCP013"], ["--only-mcp"]]) {
    const { stdout, status } = run(["scan", "test-fixtures/vulnerable/mcp-tool-sinks", ...scope, "--output", out]);
    assert.equal(status, 0, scope.join(" "));
    assert.match(stdout, /MCP013/, scope.join(" "));
    const report = JSON.parse(fs.readFileSync(out, "utf8"));
    const files = report.groups.filter((g) => g.ruleId === "MCP013").flatMap((g) => g.occurrences.map((o) => o.file));
    assert.ok(files.some((f) => f.endsWith("git_server.ts")), `${scope.join(" ")}: ${files.join(", ")}`);
  }
});

test("installed audits the configs and skills under $HOME through the CLI", () => {
  const home = fs.mkdtempSync(path.join(os.tmpdir(), "secureai-cli-home-"));
  try {
    fs.mkdirSync(path.join(home, ".cursor"), { recursive: true });
    fs.writeFileSync(
      path.join(home, ".cursor", "mcp.json"),
      JSON.stringify({ mcpServers: { mail: { command: "npx", args: ["-y", "postmark-mcp@1.0.16"] } } }, null, 2),
    );
    const env = { ...process.env, HOME: home, USERPROFILE: home, XDG_CONFIG_HOME: path.join(home, ".config") };
    const found = run(["installed", "--fail-on", "high"], { env });
    assert.equal(found.status, 1, "--fail-on must fail on the malicious package");
    assert.match(found.stdout, /Found 1 MCP server\(s\) across 1 client config\(s\)/);
    assert.match(found.stdout, /DEP003/);
    assert.match(found.stdout, /~\/\.cursor\/mcp\.json/);

    fs.rmSync(path.join(home, ".cursor"), { recursive: true, force: true });
    const empty = run(["installed"], { env });
    assert.equal(empty.status, 0);
    assert.match(empty.stdout, /No MCP client configs or Agent Skills found/);
  } finally {
    fs.rmSync(home, { recursive: true, force: true });
  }
});

test("--help lists the full MCP rule range for --only-mcp", () => {
  const { stdout } = run(["scan", "--help"]);
  assert.match(stdout, /MCP001–MCP014/);
});

for (const ruleId of ["AI001", "MCP010", "MCP013", "MCP014", "SKL001", "SKL004", "SKL005", "DEP003"]) {
  test(`explain ${ruleId} renders without throwing`, () => {
    const { stdout, status } = run(["explain", ruleId]);
    assert.equal(status, 0);
    assert.match(stdout, new RegExp(ruleId));
    assert.match(stdout, /Why this is dangerous/);
  });
}

test("explain renders the versioned OWASP 2026 mapping", () => {
  const { stdout, status } = run(["explain", "AI003"]);
  assert.equal(status, 0);
  assert.match(stdout, /OWASP LLM06:2026 \(Unbounded Consumption\)/);
});

test("--version prints a bare semver, matching package.json", () => {
  const { stdout, status } = run(["--version"]);
  assert.equal(status, 0);
  assert.match(stdout.trim(), /^\d+\.\d+\.\d+$/);
});
