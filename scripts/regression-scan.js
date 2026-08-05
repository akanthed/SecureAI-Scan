#!/usr/bin/env node
/**
 * Real-world regression scan: clones a curated set of public repos that use
 * LLM/MCP/RAG SDKs and scans each with the built CLI. The internal
 * test-fixtures corpus (test/corpus.test.js) only proves the scanner behaves
 * on code we wrote ourselves; this catches false positives against code we
 * didn't — real SDK examples, official MCP servers, framework internals.
 *
 * This IS a gate, against a committed baseline (test/regression-baseline.json)
 * of the `proven`/`likely` findings already reviewed by hand. Upstream repos
 * change, so the baseline is keyed on `repo|rule|file` rather than line
 * numbers, and only *new* fingerprints fail. Every new fingerprint must be
 * reviewed against its source line before being accepted: if it isn't a
 * genuine issue it's a rule bug, and the fix belongs in the rule plus a new
 * test-fixtures/safe/ fixture — not in the baseline.
 *
 * Usage:
 *   node scripts/regression-scan.js                    scan all repos (cached clones)
 *   node scripts/regression-scan.js --fresh            re-clone everything first
 *   node scripts/regression-scan.js openai-node        scan just one repo by name
 *   node scripts/regression-scan.js --update-baseline  accept current findings
 */
import { execSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

const here = path.dirname(fileURLToPath(import.meta.url));
const root = path.resolve(here, "..");
const cacheDir = path.join(root, ".regression-cache");
const baselinePath = path.join(root, "test", "regression-baseline.json");

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
const updateBaseline = process.argv.includes("--update-baseline");
const only = process.argv.slice(2).find((a) => !a.startsWith("--"));
const targets = only ? REPOS.filter((r) => r.name === only) : REPOS;
if (only && targets.length === 0) {
  console.error(`Unknown repo "${only}". Known: ${REPOS.map((r) => r.name).join(", ")}`);
  process.exit(1);
}

fs.mkdirSync(cacheDir, { recursive: true });

/** repo|ruleId|file — deliberately line-free so upstream churn isn't noise. */
function fingerprint(repo, ruleId, file) {
  return `${repo}|${ruleId}|${file.replace(/\\/g, "/")}`;
}

const baseline = fs.existsSync(baselinePath)
  ? JSON.parse(fs.readFileSync(baselinePath, "utf-8"))
  : { fingerprints: [] };
const baselineSet = new Set(baseline.fingerprints);

const summary = [];
const observed = new Set();
const newFindings = [];

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
  const reportPath = path.join(os.tmpdir(), `secureai-regression-${repo.name}.json`);
  let output = "";
  try {
    output = execSync(
      `node "${path.join(root, "dist", "index.js")}" scan "${dest}" --limit 15 --output "${reportPath}"`,
      { encoding: "utf-8", maxBuffer: 1024 * 1024 * 32 },
    );
  } catch (err) {
    // scan exits non-zero only with --fail-on, which we don't pass here —
    // a non-zero exit means the CLI itself crashed, not "findings exist".
    output = err.stdout?.toString() ?? String(err);
  }
  console.log(output);

  let count = 0;
  if (fs.existsSync(reportPath)) {
    const report = JSON.parse(fs.readFileSync(reportPath, "utf-8"));
    for (const group of report.groups ?? []) {
      for (const occurrence of group.occurrences ?? []) {
        if (occurrence.evidence === "heuristic") continue;
        count += 1;
        const fp = fingerprint(repo.name, group.ruleId, occurrence.file);
        observed.add(fp);
        if (!baselineSet.has(fp)) {
          newFindings.push({ fp, summary: occurrence.summary, line: occurrence.line });
        }
      }
    }
    fs.rmSync(reportPath, { force: true });
  } else {
    count = "ERROR";
  }
  summary.push({ repo: repo.name, findings: count });
}

console.log(`\n${"=".repeat(70)}\nSummary\n${"=".repeat(70)}`);
for (const row of summary) {
  console.log(`  ${row.repo.padEnd(28)} ${row.findings} finding(s) at default evidence level`);
}

if (updateBaseline) {
  const merged = only
    ? [...new Set([...baseline.fingerprints.filter((f) => !f.startsWith(`${only}|`)), ...observed])]
    : [...observed];
  merged.sort();
  fs.writeFileSync(
    baselinePath,
    JSON.stringify(
      { note: "Reviewed proven/likely findings from scripts/regression-scan.js. Only add entries you have read against their source line.", updated: new Date().toISOString().slice(0, 10), fingerprints: merged },
      null,
      2,
    ) + "\n",
  );
  console.log(`\nBaseline updated: ${merged.length} fingerprint(s).`);
  process.exit(0);
}

const resolved = [...baselineSet].filter(
  (fp) => !observed.has(fp) && (!only || fp.startsWith(`${only}|`)),
);
if (resolved.length > 0) {
  console.log(`\n${resolved.length} baseline finding(s) no longer reported (upstream change or a rule fix):`);
  for (const fp of resolved.slice(0, 20)) console.log(`  - ${fp}`);
}

if (newFindings.length > 0) {
  console.error(`\n${"!".repeat(70)}`);
  console.error(`${newFindings.length} NEW proven/likely finding(s) not in the baseline:`);
  for (const f of newFindings) console.error(`  + ${f.fp}:${f.line}\n      ${f.summary}`);
  console.error(
    "\nRead each one against its source line. If it isn't a genuine issue it's a\n" +
      "rule bug: fix the rule and add the pattern to test-fixtures/safe/. Only\n" +
      "once every entry is confirmed real should you run --update-baseline.",
  );
  process.exit(1);
}

console.log("\nNo new findings against the reviewed baseline.");
