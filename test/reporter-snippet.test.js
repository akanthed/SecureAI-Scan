import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { buildReport, formatReport } from "../dist/scanner/reporter.js";

function sampleFinding(overrides = {}) {
  return {
    rule_id: "AI003",
    title: "LLM call in unauthenticated request handler",
    severity: "critical",
    file: "src/app.ts",
    line: 3,
    summary: "LLM call occurs before auth checks.",
    description: "LLM call occurs in a request handler before authentication checks.",
    recommendation: "Ensure authentication runs before invoking LLMs.",
    confidence: 0.65,
    evidence: "likely",
    ...overrides,
  };
}

function makeReport(findings, rootPath) {
  return buildReport(
    findings,
    { tool: "SecureAI-Scan", version: "0.0.0", scannedAt: "2026-01-01T00:00:00.000Z" },
    { rootPath },
  );
}

test("markdown report includes evidence tier, OWASP tag, and code snippet", () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "secureai-report-"));
  const filePath = path.join(dir, "src", "app.ts");
  fs.mkdirSync(path.dirname(filePath), { recursive: true });
  fs.writeFileSync(
    filePath,
    ["const a = 1;", "const b = 2;", "openai.chat.completions.create({});", "const c = 3;"].join("\n"),
    "utf-8",
  );

  const markdown = formatReport(makeReport([sampleFinding()], dir), "markdown");
  assert.equal(markdown.includes("LIKELY"), true);
  assert.equal(markdown.includes("OWASP LLM Top 10 2026 · LLM06 Unbounded Consumption"), true);
  assert.equal(markdown.includes("openai.chat.completions.create"), true);
});

test("sarif output is valid 2.1.0 with rules, results, and locations", () => {
  const sarif = JSON.parse(formatReport(makeReport([sampleFinding()]), "sarif"));
  assert.equal(sarif.version, "2.1.0");
  const run = sarif.runs[0];
  assert.equal(run.tool.driver.name, "SecureAI-Scan");
  assert.equal(run.tool.driver.rules[0].id, "AI003");
  assert.deepEqual(run.tool.driver.rules[0].properties.tags.includes("owasp-llm-top10-2026/llm06"), true);
  assert.equal(run.results.length, 1);
  assert.equal(run.results[0].level, "error");
  assert.equal(run.results[0].locations[0].physicalLocation.region.startLine, 3);
  assert.ok(run.results[0].partialFingerprints.secureaiScanFingerprint);
});

test("JSON report identifies the OWASP LLM framework version", () => {
  const json = JSON.parse(formatReport(makeReport([sampleFinding()]), "json"));
  assert.equal(json.groups[0].owasp, "LLM06");
  assert.equal(json.groups[0].owaspVersion, "2026");
  assert.equal(json.groups[0].owaspName, "Unbounded Consumption");
});

test("trace steps render in markdown output", () => {
  const finding = sampleFinding({
    rule_id: "AI001",
    title: "Prompt injection via user input",
    severity: "high",
    evidence: "proven",
    trace: [
      { kind: "source", file: "src/app.ts", line: 1, note: "request data `req.body.q`" },
      { kind: "sink", file: "src/app.ts", line: 3, note: "openai.chat.completions.create" },
    ],
  });
  const markdown = formatReport(makeReport([finding]), "markdown");
  assert.equal(markdown.includes("source: `src/app.ts:1`"), true);
  assert.equal(markdown.includes("sink: `src/app.ts:3`"), true);
});
