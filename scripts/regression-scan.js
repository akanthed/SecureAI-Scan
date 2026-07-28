#!/usr/bin/env node
/**
 * Real-world regression scan: clones a curated set of public repos that use
 * LLM/MCP/RAG SDKs and scans each with the built CLI. The internal
 * test-fixtures corpus (test/corpus.test.js) only proves the scanner behaves
 * on code we wrote ourselves; this catches false positives against code we
 * didn't — real SDK examples, official MCP servers, framework internals.
 *
 * Not a pass/fail gate: upstream repos change over time, so there's no
 * fixed expected-count baseline. Run it, read the findings, and use
 * judgment — every `proven`/`likely` finding here should be either a real
 * issue or a bug to fix in a rule, never "close enough."
 *
 * Usage:
 *   node scripts/regression-scan.js            scan all repos (cached clones)
 *   node scripts/regression-scan.js --fresh     re-clone everything first
 *   node scripts/regression-scan.js openai-node scan just one repo by name
 */
import { execSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const here = path.dirname(fileURLToPath(import.meta.url));
const root = path.resolve(here, "..");
const cacheDir = path.join(root, ".regression-cache");

// Diverse on purpose: different SDKs (OpenAI/Anthropic/Vercel AI/LlamaIndex),
// different languages (TS + Python), and both SDK-consumer code (examples/
// tests) and SDK-author code (the SDKs' own source) — false positives show
// up differently in each.
//
// anthropic-skills and cisco-skill-scanner were added for the SKL001-005
// evasion-resistance work (v0.6.0): anthropics/skills is the canonical,
// large (18-bundle) real-world Agent Skill corpus and is the best available
// precision check for the bundle rules; cisco-ai-defense/skill-scanner ships
// its own eval corpus under evals/skills and evals/test_skills with
// _expected.json labels and directories literally named malicious/ and
// safe/ — a rare case where a "real-world" repo doubles as a labeled
// recall+precision test, not just a precision one. Findings there should be
// read against the file's directory label, not assumed to be false
// positives by default the way the rest of this script's repos are.
const REPOS = [
  { name: "openai-node", url: "https://github.com/openai/openai-node.git" },
  { name: "anthropic-sdk-typescript", url: "https://github.com/anthropics/anthropic-sdk-typescript.git" },
  { name: "anthropic-sdk-python", url: "https://github.com/anthropics/anthropic-sdk-python.git" },
  { name: "typescript-sdk", url: "https://github.com/modelcontextprotocol/typescript-sdk.git" },
  { name: "servers", url: "https://github.com/modelcontextprotocol/servers.git" },
  { name: "ai", url: "https://github.com/vercel/ai.git" },
  { name: "llama_index", url: "https://github.com/run-llama/llama_index.git" },
  { name: "anthropic-skills", url: "https://github.com/anthropics/skills.git" },
  { name: "cisco-skill-scanner", url: "https://github.com/cisco-ai-defense/skill-scanner.git" },
];

const fresh = process.argv.includes("--fresh");
const only = process.argv.slice(2).find((a) => !a.startsWith("--"));
const targets = only ? REPOS.filter((r) => r.name === only) : REPOS;
if (only && targets.length === 0) {
  console.error(`Unknown repo "${only}". Known: ${REPOS.map((r) => r.name).join(", ")}`);
  process.exit(1);
}

fs.mkdirSync(cacheDir, { recursive: true });

const summary = [];

for (const repo of targets) {
  const dest = path.join(cacheDir, repo.name);
  if (fresh && fs.existsSync(dest)) {
    fs.rmSync(dest, { recursive: true, force: true });
  }
  if (!fs.existsSync(dest)) {
    console.log(`Cloning ${repo.name}...`);
    execSync(`git clone --depth 1 ${repo.url} "${dest}"`, { stdio: "inherit" });
  }

  console.log(`\n${"=".repeat(70)}\nScanning ${repo.name}\n${"=".repeat(70)}`);
  let output = "";
  try {
    output = execSync(`node "${path.join(root, "dist", "index.js")}" scan "${dest}" --limit 15`, {
      encoding: "utf-8",
      maxBuffer: 1024 * 1024 * 32,
    });
  } catch (err) {
    // scan exits non-zero only with --fail-on, which we don't pass here —
    // a non-zero exit means the CLI itself crashed, not "findings exist".
    output = err.stdout?.toString() ?? String(err);
  }
  console.log(output);

  const findingsMatch = output.match(/(\d+) finding\(s\)/);
  summary.push({
    repo: repo.name,
    findings: findingsMatch ? Number(findingsMatch[1]) : output.includes("No findings") ? 0 : "ERROR",
  });
}

console.log(`\n${"=".repeat(70)}\nSummary\n${"=".repeat(70)}`);
for (const row of summary) {
  console.log(`  ${row.repo.padEnd(28)} ${row.findings} finding(s) at default evidence level`);
}
console.log(
  "\nReview every finding above against its source line. Any that isn't a\n" +
    "genuine issue is a rule bug — fix the rule and add the offending pattern\n" +
    "as a new test-fixtures/safe/ regression fixture before merging.",
);
