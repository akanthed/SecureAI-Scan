import test from "node:test";
import assert from "node:assert/strict";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { scanRepositoryDetailed } from "../dist/scanner/scan.js";

/**
 * Precision gate: every vulnerable fixture must fire its rule at proven or
 * likely evidence, and NO safe fixture may produce any proven/likely finding.
 * This is the contract behind "a default scan only reports what it can prove".
 */

const here = path.dirname(fileURLToPath(import.meta.url));
const fixturesRoot = path.resolve(here, "..", "test-fixtures");

const result = scanRepositoryDetailed(fixturesRoot);
const defaultTier = result.findings.filter((f) => f.evidence !== "heuristic");

function norm(p) {
  return p.replace(/\\/g, "/").toLowerCase();
}

function has(ruleId, fileSubstring) {
  return defaultTier.some(
    (f) => f.rule_id === ruleId && norm(f.file).includes(norm(fileSubstring)),
  );
}

const EXPECTED_VULNERABLE = [
  ["AI001", "vulnerable/prompt_injection.ts"],
  ["AI001", "vulnerable/rag_app.py"],
  ["AI002", "vulnerable/logging.ts"],
  ["AI003", "vulnerable/llm_before_auth.ts"],
  ["AI004", "vulnerable/pii_to_llm.ts"],
  ["AI005", "vulnerable/unsafe_output.ts"],
  ["MCP004", "vulnerable/mcp/.mcp.json"],
  ["MCP005", "vulnerable/mcp/.mcp.json"],
  ["MCP006", "vulnerable/mcp/.mcp.json"],
  ["MCP007", "vulnerable/tool_poisoning.ts"],
  ["MCP008", "vulnerable/tool_poisoning.ts"],
  ["MCP009", "vulnerable/tool_poisoning.ts"],
  ["MCP007", "vulnerable/tool_poisoning.py"],
  ["MCP008", "vulnerable/tool_poisoning.py"],
  ["MCP009", "vulnerable/tool_poisoning.py"],
];

for (const [ruleId, file] of EXPECTED_VULNERABLE) {
  test(`recall: ${ruleId} fires on ${file}`, () => {
    assert.equal(
      has(ruleId, file),
      true,
      `Expected ${ruleId} in ${file}. Findings there: ${JSON.stringify(
        defaultTier.filter((f) => norm(f.file).includes(norm(file))).map((f) => f.rule_id),
      )}`,
    );
  });
}

test("precision: safe fixtures produce zero proven/likely findings", () => {
  const safeHits = defaultTier.filter((f) => norm(f.file).includes("safe/"));
  assert.deepEqual(
    safeHits.map((f) => `${f.rule_id} ${f.file}:${f.line} [${f.evidence}]`),
    [],
    "Safe fixtures must be clean at the default evidence level",
  );
});

test("AI001 finding carries a source→sink trace", () => {
  const ai001 = defaultTier.find(
    (f) => f.rule_id === "AI001" && norm(f.file).includes("vulnerable/prompt_injection.ts"),
  );
  assert.ok(ai001, "AI001 finding expected");
  assert.ok(Array.isArray(ai001.trace) && ai001.trace.length >= 2, "trace expected");
  assert.equal(ai001.trace[0].kind, "source");
  assert.equal(ai001.trace[ai001.trace.length - 1].kind, "sink");
  assert.equal(ai001.evidence, "proven");
});
