import { test } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { execFileSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { hits, scanDir, applyPatch, cloneForPatch, PatchError } from "../scripts/corpus/lib.js";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const runner = path.join(root, "scripts", "corpus-run.js");
const BROKEN = "--- a/nope.ts\n+++ b/nope.ts\n@@ -1 +1 @@\n-x\n+y\n";

function fixtureDir(...files) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "corpus-scan-"));
  for (const f of files) fs.copyFileSync(path.join(root, "test-fixtures", f), path.join(dir, path.basename(f)));
  return dir;
}

test("hits() counts only proven/likely and normalises separators", () => {
  const findings = [
    { ruleId: "MCP013", file: "a/b.ts", evidence: "proven" },
    { ruleId: "MCP013", file: "a/b.ts", evidence: "likely" },
    { ruleId: "MCP013", file: "a/b.ts", evidence: "heuristic" },
    { ruleId: "MCP014", file: "a/b.ts", evidence: "proven" },
  ];
  assert.equal(hits(findings, { rule: "MCP013" }), 2);
  assert.equal(hits(findings, { rule: "MCP013", file: "a\\b.ts" }), 2);
  assert.equal(hits(findings, { rule: "MCP013", file: "other.ts" }), 0);
});

test("scanDir() flags the vulnerable fixture and clears the safe one", () => {
  const bad = scanDir(fixtureDir("vulnerable/mcp-tool-sinks/git_server.ts"));
  assert.equal(bad.ok, true);
  assert.ok(hits(bad.findings, { rule: "MCP013" }) >= 1);
  const good = scanDir(fixtureDir("safe/mcp-tool-sinks/guarded_servers.ts"));
  assert.equal(hits(good.findings, { rule: "MCP013" }), 0);
});

test("applyPatch() reports a broken patch as PatchError", () => {
  const dir = cloneForPatch(fixtureDir("vulnerable/mcp-tool-sinks/git_server.ts"));
  const bad = path.join(dir, "bad.patch");
  fs.writeFileSync(bad, BROKEN);
  assert.throws(() => applyPatch(dir, bad), PatchError);
});

// A tiny local git repo: a vulnerable commit, a fix commit, and one mutation patch.
function fakeCorpus({ brokenPatch = false } = {}) {
  const work = fs.mkdtempSync(path.join(os.tmpdir(), "corpus-fake-"));
  const repo = path.join(work, "repo");
  fs.mkdirSync(repo);
  const sh = (...a) =>
    execFileSync("git", ["-c", "user.email=t@t", "-c", "user.name=t", "-c", "uploadpack.allowAnySHA1InWant=true", ...a], { cwd: repo, encoding: "utf-8" }).trim();
  sh("init", "-q");
  sh("config", "uploadpack.allowAnySHA1InWant", "true");
  fs.copyFileSync(path.join(root, "test-fixtures", "vulnerable", "mcp-tool-sinks", "git_server.ts"), path.join(repo, "server.ts"));
  sh("add", ".");
  sh("commit", "-qm", "vuln");
  const vuln = sh("rev-parse", "HEAD");
  fs.appendFileSync(path.join(repo, "server.ts"), "\n// harmless mutation\n");
  const diff = sh("diff") + "\n";
  sh("checkout", "--", "server.ts");
  fs.copyFileSync(path.join(root, "test-fixtures", "safe", "mcp-tool-sinks", "guarded_servers.ts"), path.join(repo, "server.ts"));
  sh("commit", "-qam", "fix");
  const fix = sh("rev-parse", "HEAD");
  const patch = path.join(work, "m.patch");
  fs.writeFileSync(patch, brokenPatch ? BROKEN : diff);
  const url = repo.replace(/\\/g, "/");
  const manifest = path.join(work, "cases.json");
  fs.writeFileSync(
    manifest,
    JSON.stringify({ cases: [{ id: "FAKE-1", repo: url, vulnerableSha: vuln, fixSha: fix, rule: "MCP013", mutations: [{ name: "comment", kind: "recall", patch }] }] }),
  );
  const clean = path.join(work, "clean.json");
  fs.writeFileSync(clean, JSON.stringify({ servers: [] }));
  return { work, manifest, clean, url, vuln, fix };
}

function run(args) {
  try {
    return { code: 0, out: execFileSync(process.execPath, [runner, ...args], { encoding: "utf-8", stdio: ["ignore", "pipe", "pipe"] }) };
  } catch (e) {
    return { code: e.status, out: String(e.stdout) + String(e.stderr) };
  }
}

test("runner scores a fake case and writes --json", () => {
  const { work, manifest, clean } = fakeCorpus();
  const json = path.join(work, "out.json");
  const r = run(["--cases", manifest, "--clean", clean, "--cache", path.join(work, "cache"), "--json", json]);
  assert.equal(r.code, 0, r.out);
  const report = JSON.parse(fs.readFileSync(json, "utf-8"));
  assert.deepEqual(report.recall.vulnerable, { passed: 1, total: 1 });
  assert.deepEqual(report.precision.fixed, { passed: 1, total: 1 });
  assert.deepEqual(report.recall.mutations, { passed: 1, total: 1 });
  assert.ok(report.scanner.version);
});

test("runner reports a broken patch as an error, not a recall miss", () => {
  const { work, manifest, clean } = fakeCorpus({ brokenPatch: true });
  const r = run(["--cases", manifest, "--clean", clean, "--cache", path.join(work, "cache")]);
  assert.notEqual(r.code, 0);
  assert.match(r.out, /failed to apply/);
});

test("--scanner-cmd is honoured", () => {
  const { work, manifest, clean } = fakeCorpus();
  const stub = path.join(work, "stub.cjs");
  fs.writeFileSync(stub, 'require("fs").writeFileSync(process.argv[3], JSON.stringify({groups:[]}))');
  const cmd = `node "${stub.replace(/\\/g, "/")}" {dir} {out}`;
  const r = run(["--cases", manifest, "--clean", clean, "--cache", path.join(work, "cache"), "--scanner-cmd", cmd]);
  assert.notEqual(r.code, 0); // stub reports nothing, so the vulnerable side misses
  assert.match(r.out, /MISS/);
});

test("clean set fails on a finding and names the server", () => {
  const { work, manifest, url, vuln, fix } = fakeCorpus();
  const clean = path.join(work, "clean2.json");
  fs.writeFileSync(clean, JSON.stringify({ servers: [{ name: "fake-vuln", repo: url, sha: vuln }, { name: "fake-safe", repo: url, sha: fix }] }));
  const r = run(["--cases", manifest, "--clean", clean, "--cache", path.join(work, "cache"), "--clean-only"]);
  assert.notEqual(r.code, 0);
  assert.match(r.out, /fake-vuln/);
});
