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
  ["MCP002", "vulnerable/mcp_dynamic_url.ts"],
  ["MCP010", "vulnerable/mcp_dynamic_command.ts"],
  ["SKL001", "vulnerable/skills/leaky-skill/SKILL.md"],
  ["SKL002", "vulnerable/skills/leaky-skill/SKILL.md"],
  ["SKL003", "vulnerable/skills/leaky-skill/SKILL.md"],
  // Evasion-resistance: each of these fixtures is cloaked with a technique
  // from arXiv:2607.02357 that defeated the scanners surveyed there.
  ["SKL002", "vulnerable/skills/cloaked-skill/SKILL.md"],
  ["SKL004", "vulnerable/skills/staged-skill/SKILL.md"],
  ["SKL005", "vulnerable/skills/exfil-skill/helpers/metrics.test.ts"],
  // Recall gaps found by running against real-world labeled fixtures
  // (cisco-ai-defense/skill-scanner's evals/ corpus) — see CHANGELOG 0.6.1.
  ["SKL005", "vulnerable/skills/env-harvest-skill/collect.py"],
  ["SKL005", "vulnerable/skills/deferred-exec-skill/updater.py"],
  // Backfilled recall coverage — these six rules were registered and shipping
  // with no fixture-corpus proof they still fire (docs/PROJECT_AUDIT.md §1.3).
  ["AI011", "vulnerable/multiagent_trust.ts"],
  ["MCP001", "vulnerable/mcp_tool_metadata.ts"],
  ["MCP003", "vulnerable/mcp_tool_result.ts"],
  ["AI012", "vulnerable/unvalidated_structured_output.ts"],
  ["VEC002", "vulnerable/vec_unbounded_search.ts"],
  ["VEC003", "vulnerable/vec_user_ingestion.ts"],
  ["VEC004", "vulnerable/vec_ingest_no_namespace.ts"],
  // Phase C — AI001 interprocedural (cross-function/cross-file) taint trace.
  ["AI001", "vulnerable/multihop/two_file/lib/llmclient.ts"],
  ["AI001", "vulnerable/multihop/three_file/lib/llmclient.ts"],
  ["AI001", "vulnerable/multihop/mutual_recursion/b.ts"],
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

test("AI001 interprocedural (2-file) finding has a multi-hop, cross-file trace capped below proven", () => {
  const finding = defaultTier.find(
    (f) => f.rule_id === "AI001" && norm(f.file).includes("vulnerable/multihop/two_file/lib/llmclient.ts"),
  );
  assert.ok(finding, "interprocedural AI001 finding expected");
  assert.ok(finding.trace.length > 2, "expected more than a single-function 2-3 step trace");
  const files = new Set(finding.trace.map((s) => norm(s.file)));
  assert.ok(files.size > 1, "expected the trace to span more than one file");
  assert.notEqual(finding.evidence, "proven", "interprocedural findings must never be proven");
});

test("AI001 interprocedural (3-file, 2-hop) finding still fires within the hop cap", () => {
  const finding = defaultTier.find(
    (f) => f.rule_id === "AI001" && norm(f.file).includes("vulnerable/multihop/three_file/lib/llmclient.ts"),
  );
  assert.ok(finding, "3-file interprocedural AI001 finding expected");
  const files = new Set(finding.trace.map((s) => norm(s.file)));
  assert.ok(files.size >= 3, "expected the trace to span all three files in the chain");
});

test("AI001 interprocedural walk is cycle-safe: mutual recursion yields exactly one finding", () => {
  const hits = defaultTier.filter(
    (f) => f.rule_id === "AI001" && norm(f.file).includes("vulnerable/multihop/mutual_recursion/"),
  );
  assert.equal(hits.length, 1, `expected exactly one finding, got ${JSON.stringify(hits.map((f) => `${f.file}:${f.line}`))}`);
});
