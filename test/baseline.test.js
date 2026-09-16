import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { applyBaseline } from "../dist/scanner/baseline.js";

function mkFinding(overrides = {}) {
  return {
    rule_id: "AI003",
    title: "LLM call before authentication",
    severity: "critical",
    file: "src/app.ts",
    line: 12,
    summary: "LLM call occurs before auth checks.",
    description: "LLM call occurs before auth checks.",
    recommendation: "Add auth before LLM call.",
    confidence: 0.4,
    ...overrides,
  };
}

test("applyBaseline creates baseline on first run", () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "secureai-baseline-"));
  const baselinePath = path.join(dir, "baseline.json");
  const first = applyBaseline(baselinePath, [mkFinding()]);

  assert.equal(first.created, true);
  assert.equal(first.newOrRegressedCount, 1);
  assert.equal(fs.existsSync(baselinePath), true);

  const parsed = JSON.parse(fs.readFileSync(baselinePath, "utf-8"));
  assert.equal(parsed.schema, "secureai-baseline/v1");
  assert.equal(parsed.findings[0].rule_id, "AI003");
});

test("applyBaseline returns only new or regressed findings on later runs", () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "secureai-baseline-"));
  const baselinePath = path.join(dir, "baseline.json");
  applyBaseline(baselinePath, [mkFinding()]);

  const nextRun = applyBaseline(baselinePath, [
    mkFinding({ confidence: 0.41 }),
    mkFinding({ file: "src/new.ts", line: 9 }),
  ]);

  assert.equal(nextRun.created, false);
  assert.equal(nextRun.newOrRegressedCount, 2);
  assert.equal(nextRun.baselineCount, 1);
  assert.equal(nextRun.currentCount, 2);
});
