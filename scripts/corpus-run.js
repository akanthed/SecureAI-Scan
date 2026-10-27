#!/usr/bin/env node
/**
 * Recall/precision corpus for MCP013/MCP014. Each case pins a vulnerable and a
 * fixed commit of a real MCP server with a published command-injection CVE:
 *   - vulnerable commit must fire (recall)
 *   - fix commit must stay clean (precision)
 *   - "recall" mutations (harmless refactors patched onto the vulnerable
 *     commit) must still fire
 *   - "guard" mutations (a real guard in a different style, patched onto the
 *     fix commit) must stay clean
 * plus a clean set of unrelated servers that must produce no MCP013/MCP014.
 * See docs/Corpus.md.
 *
 * Usage:
 *   node scripts/corpus-run.js [--only <case-id>] [--clean-only] [--json <path>]
 *        [--scanner-cmd "<cmd with {dir} and {out}>"] [--cases <file>] [--clean <file>] [--cache <dir>]
 */
import fs from "node:fs";
import path from "node:path";
import { applyPatch, checkoutAt, cloneForPatch, hits, PatchError, root, scanDir } from "./corpus/lib.js";

const argv = process.argv.slice(2);
const flag = (name) => argv.includes(`--${name}`);
const opt = (name) => {
  const i = argv.indexOf(`--${name}`);
  return i >= 0 ? argv[i + 1] : undefined;
};

const casesPath = path.resolve(opt("cases") ?? path.join(root, "corpus", "cases.json"));
const cleanPath = path.resolve(opt("clean") ?? path.join(root, "corpus", "clean.json"));
const cacheDir = path.resolve(opt("cache") ?? path.join(root, ".corpus-cache"));
const scannerCmd = opt("scanner-cmd");
const only = opt("only");
const cleanOnly = flag("clean-only");
const CLEAN_RULES = ["MCP013", "MCP014"];

fs.mkdirSync(cacheDir, { recursive: true });
const readJson = (p) => JSON.parse(fs.readFileSync(p, "utf-8").replace(/^﻿/, ""));
const pkg = readJson(path.join(root, "package.json"));
const cases = cleanOnly ? [] : readJson(casesPath).cases.filter((c) => !only || c.id === only);
if (only && cases.length === 0 && !cleanOnly) {
  console.error(`Unknown case "${only}".`);
  process.exit(1);
}
const servers = only && !cleanOnly ? [] : fs.existsSync(cleanPath) ? readJson(cleanPath).servers ?? [] : [];

const rows = [];
function record(group, id, label, status, detail = "") {
  rows.push({ group, id, label, status, detail });
  const mark = status === "pass" ? "ok  " : status.toUpperCase().padEnd(4);
  console.log(`  ${mark} ${id} ${label}${detail ? ` -- ${detail}` : ""}`);
}

/** Scans dir; returns hit count or null (and records an ERROR) if the scanner produced no report. */
function score(group, id, label, dir, rule) {
  const r = scanDir(dir, scannerCmd);
  if (!r.ok) {
    record(group, id, label, "error", "scanner wrote no report");
    return null;
  }
  return hits(r.findings, { rule });
}

for (const c of cases) {
  console.log(`\n${c.id} (${c.rule})`);
  let vuln, fixed;
  try {
    vuln = checkoutAt(c.repo, c.vulnerableSha, cacheDir);
    fixed = checkoutAt(c.repo, c.fixSha, cacheDir);
  } catch (err) {
    record("vulnerable", c.id, "checkout", "error", err.message);
    continue;
  }
  const v = score("vulnerable", c.id, "vulnerable commit", vuln, c.rule);
  if (v !== null) record("vulnerable", c.id, "vulnerable commit", v >= 1 ? "pass" : "miss", `${v} finding(s)`);
  const f = score("fixed", c.id, "fix commit", fixed, c.rule);
  if (f !== null) record("fixed", c.id, "fix commit", f === 0 ? "pass" : "false-positive", `${f} finding(s)`);

  for (const m of c.mutations ?? []) {
    const group = m.kind === "guard" ? "guards" : "mutations";
    const label = `${m.kind}:${m.name}`;
    const scratch = cloneForPatch(m.kind === "guard" ? fixed : vuln);
    try {
      applyPatch(scratch, path.resolve(path.dirname(casesPath), m.patch));
    } catch (err) {
      record(group, c.id, label, "error", err instanceof PatchError ? err.message : String(err));
      fs.rmSync(scratch, { recursive: true, force: true });
      continue;
    }
    const n = score(group, c.id, label, scratch, c.rule);
    fs.rmSync(scratch, { recursive: true, force: true });
    if (n === null) continue;
    if (m.kind === "guard") record(group, c.id, label, n === 0 ? "pass" : "false-positive", `${n} finding(s)`);
    else record(group, c.id, label, n >= 1 ? "pass" : "miss", `${n} finding(s)`);
  }
}

if (servers.length > 0) console.log(`\nClean set (${CLEAN_RULES.join("/")} must be silent)`);
for (const s of servers) {
  let dir;
  try {
    dir = checkoutAt(s.repo, s.sha, cacheDir);
  } catch (err) {
    record("clean", s.name, "checkout", "error", err.message);
    continue;
  }
  const r = scanDir(dir, scannerCmd);
  if (!r.ok) {
    record("clean", s.name, "clean server", "error", "scanner wrote no report");
    continue;
  }
  const n = CLEAN_RULES.reduce((sum, rule) => sum + hits(r.findings, { rule }), 0);
  record("clean", s.name, "clean server", n === 0 ? "pass" : "false-positive", `${n} finding(s)`);
}

const tally = (group) => {
  const g = rows.filter((r) => r.group === group);
  return { passed: g.filter((r) => r.status === "pass").length, total: g.length };
};
const report = {
  generated: new Date().toISOString(),
  scanner: { name: scannerCmd ? "custom" : pkg.name, version: scannerCmd ? "custom" : pkg.version },
  recall: { vulnerable: tally("vulnerable"), mutations: tally("mutations") },
  precision: { fixed: tally("fixed"), guards: tally("guards"), clean: tally("clean") },
  cases: rows,
};

const fmt = (t) => `${t.passed}/${t.total}`;
console.log(`\n${"=".repeat(60)}\nRecall      vulnerable ${fmt(report.recall.vulnerable)}   mutations ${fmt(report.recall.mutations)}`);
console.log(`Precision   fixed ${fmt(report.precision.fixed)}   guards ${fmt(report.precision.guards)}   clean set ${fmt(report.precision.clean)}`);

const jsonPath = opt("json");
if (jsonPath) fs.writeFileSync(jsonPath, JSON.stringify(report, null, 2) + "\n");

const failed = rows.filter((r) => r.status !== "pass");
if (failed.length > 0) {
  console.error(`\n${failed.length} case(s) did not pass:`);
  for (const r of failed) console.error(`  ${r.status.toUpperCase()}  ${r.id} ${r.label}${r.detail ? ` -- ${r.detail}` : ""}`);
  process.exit(1);
}
console.log("\nAll corpus cases passed.");
