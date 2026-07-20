import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { scanDependencyFilesForRisks, scanKnownMaliciousPackages } from "../dist/scanner/dependency-guard.js";

class FakeChecker {
  async exists(ecosystem, name) {
    if (ecosystem === "npm" && name === "hallucinated-pkg") {
      return false;
    }
    return true;
  }
}

test("dependency guard flags missing and suspicious dependency names", async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "secureai-deps-"));

  fs.writeFileSync(
    path.join(dir, "package.json"),
    JSON.stringify(
      {
        name: "tmp",
        version: "1.0.0",
        dependencies: {
          opena1: "1.0.0",
          "hallucinated-pkg": "1.0.0",
        },
      },
      null,
      2,
    ),
  );

  fs.writeFileSync(path.join(dir, "requirements.txt"), "reqests==2.31.0\n");

  const findings = await scanDependencyFilesForRisks({
    rootPath: dir,
    checker: new FakeChecker(),
  });

  const ruleIds = findings.map((f) => f.rule_id);
  assert.equal(ruleIds.includes("DEP001"), true);
  assert.equal(ruleIds.includes("DEP002"), true);
});

test("DEP003 flags known-malicious packages in package.json and MCP configs, offline", () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "secureai-advisories-"));

  fs.writeFileSync(
    path.join(dir, "package.json"),
    JSON.stringify(
      { name: "tmp", version: "1.0.0", dependencies: { "postmark-mcp": "1.0.16", express: "4.0.0" } },
      null,
      2,
    ),
  );
  fs.writeFileSync(
    path.join(dir, ".mcp.json"),
    JSON.stringify(
      { mcpServers: { remote: { command: "npx", args: ["-y", "mcp-remote@0.1.0", "https://example.com/mcp"] } } },
      null,
      2,
    ),
  );

  const findings = scanKnownMaliciousPackages(dir);
  const byName = findings.map((f) => `${f.rule_id}:${f.file}`);

  assert.equal(findings.every((f) => f.rule_id === "DEP003"), true);
  assert.equal(findings.some((f) => f.file === "package.json" && f.severity === "critical"), true);
  assert.equal(findings.some((f) => f.file === ".mcp.json" && f.severity === "high"), true);
  assert.equal(findings.length, 2, `unexpected findings: ${JSON.stringify(byName)}`);
});

test("DEP003 stays silent on clean dependencies", () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "secureai-advisories-clean-"));
  fs.writeFileSync(
    path.join(dir, "package.json"),
    JSON.stringify({ name: "tmp", version: "1.0.0", dependencies: { openai: "4.0.0" } }, null, 2),
  );
  assert.deepEqual(scanKnownMaliciousPackages(dir), []);
});

test("dependency guard fails open (and warns once) when the registry is unreachable", async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "secureai-deps-offline-"));
  fs.writeFileSync(
    path.join(dir, "package.json"),
    JSON.stringify({ name: "tmp", version: "1.0.0", dependencies: { openai: "1.0.0" } }, null, 2),
  );

  const originalFetch = global.fetch;
  const originalStderrWrite = process.stderr.write;
  let stderrOutput = "";
  global.fetch = async () => {
    throw new Error("simulated network failure");
  };
  process.stderr.write = (chunk) => {
    stderrOutput += chunk;
    return true;
  };

  let findings;
  try {
    // No injected checker: exercises the real RegistryExistenceChecker's
    // fetch-failure path, not the FakeChecker used above.
    findings = await scanDependencyFilesForRisks({ rootPath: dir });
  } finally {
    global.fetch = originalFetch;
    process.stderr.write = originalStderrWrite;
  }

  // Fail-open: a network error must never manufacture a false "package not
  // found" finding.
  assert.equal(findings.some((f) => f.rule_id === "DEP001"), false);
  assert.match(stderrOutput, /could not reach package registry/i);
});
