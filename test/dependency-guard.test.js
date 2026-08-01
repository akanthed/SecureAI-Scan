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

test("DEP001 does not treat a scoped npm package name as unreasonable (found while scanning this repo's own package.json: @types/node was flagged 'not found' before ever reaching the registry)", async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "secureai-deps-scoped-"));

  fs.writeFileSync(
    path.join(dir, "package.json"),
    JSON.stringify(
      { name: "tmp", version: "1.0.0", dependencies: { "@types/node": "^22.0.0" } },
      null,
      2,
    ),
  );

  const findings = await scanDependencyFilesForRisks({
    rootPath: dir,
    checker: new FakeChecker(),
  });

  assert.equal(
    findings.some((f) => f.rule_id === "DEP001"),
    false,
    "a well-formed scoped package name must not be rejected before the registry check runs",
  );
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

test("DEP003 clears a package once it's pinned to a version outside the affected range (vulnerable → patched)", () => {
  // mcp-remote CVE-2025-6514 is fixed at 0.1.16 ("<0.1.16" is the affected
  // range). This is the exact "scan the vulnerable version, then scan the
  // patched version" check: the vulnerable pin must still fire, and the
  // patched pin — a real fix that ships today — must not.
  const vulnDir = fs.mkdtempSync(path.join(os.tmpdir(), "secureai-cve-vuln-"));
  fs.writeFileSync(
    path.join(vulnDir, "package.json"),
    JSON.stringify({ name: "tmp", version: "1.0.0", dependencies: { "mcp-remote": "0.1.15" } }, null, 2),
  );
  const vulnFindings = scanKnownMaliciousPackages(vulnDir);
  assert.equal(vulnFindings.length, 1, `expected the vulnerable pin to be flagged: ${JSON.stringify(vulnFindings)}`);
  assert.equal(vulnFindings[0].rule_id, "DEP003");

  const patchedDir = fs.mkdtempSync(path.join(os.tmpdir(), "secureai-cve-patched-"));
  fs.writeFileSync(
    path.join(patchedDir, "package.json"),
    JSON.stringify({ name: "tmp", version: "1.0.0", dependencies: { "mcp-remote": "0.1.16" } }, null, 2),
  );
  const patchedFindings = scanKnownMaliciousPackages(patchedDir);
  assert.deepEqual(patchedFindings, [], `expected the patched pin to be clear: ${JSON.stringify(patchedFindings)}`);
});

test("DEP003 keeps flagging a malicious package across its later versions (no legitimate patch exists)", () => {
  // postmark-mcp's backdoor is the package itself, not a fixable bug — every
  // version from 1.0.16 onward is still the same malicious actor's release.
  // Version-range gating must not accidentally clear later pins.
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "secureai-malicious-later-"));
  fs.writeFileSync(
    path.join(dir, "package.json"),
    JSON.stringify({ name: "tmp", version: "1.0.0", dependencies: { "postmark-mcp": "1.0.20" } }, null, 2),
  );
  const findings = scanKnownMaliciousPackages(dir);
  assert.equal(findings.length, 1);
  assert.equal(findings[0].rule_id, "DEP003");
});

test("DEP003 does not flag postmark-mcp's pre-backdoor version (1.0.15, before the malicious 1.0.16 release)", () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "secureai-pre-backdoor-"));
  fs.writeFileSync(
    path.join(dir, "package.json"),
    JSON.stringify({ name: "tmp", version: "1.0.0", dependencies: { "postmark-mcp": "1.0.15" } }, null, 2),
  );
  assert.deepEqual(scanKnownMaliciousPackages(dir), []);
});

test("DEP003 fails toward flagging when the declared version is a range, not an exact pin", () => {
  // "^0.1.16" could still resolve to a vulnerable 0.1.x release depending on
  // what's actually installed — ambiguity must never silently clear a
  // proven-tier finding.
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "secureai-cve-range-"));
  fs.writeFileSync(
    path.join(dir, "package.json"),
    JSON.stringify({ name: "tmp", version: "1.0.0", dependencies: { "mcp-remote": "^0.1.16" } }, null, 2),
  );
  const findings = scanKnownMaliciousPackages(dir);
  assert.equal(findings.length, 1, "an unpinned range must still be flagged, not silently cleared");
});

test("DEP003 still detects a malicious package when package.json has a UTF-8 BOM (Windows-saved files)", () => {
  // Found while manually re-verifying the version-gating fix above: a file
  // written with a leading BOM (PowerShell's default `Set-Content -Encoding
  // utf8`, some Windows editors) broke JSON.parse, and the bare try/catch
  // around it silently produced zero candidates — DEP001/002/003 all
  // quietly no-op with no error, no warning, nothing.
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "secureai-bom-"));
  const withBom = "﻿" + JSON.stringify({ name: "tmp", version: "1.0.0", dependencies: { "postmark-mcp": "1.0.16" } });
  fs.writeFileSync(path.join(dir, "package.json"), withBom, "utf-8");

  const findings = scanKnownMaliciousPackages(dir);
  assert.equal(findings.length, 1, "a BOM must not silently swallow the finding");
  assert.equal(findings[0].rule_id, "DEP003");
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
