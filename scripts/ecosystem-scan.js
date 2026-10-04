#!/usr/bin/env node
/**
 * Ecosystem audit: fetch public MCP servers (nothing fetched is executed),
 * scan each with the full rule set, and write a PRIVATE triage report.
 *
 * This is how the scanner earns trust and finds its own bugs: every finding
 * is read against its source line. A false positive is a rule bug (fix it,
 * add a test-fixtures/safe/ fixture). A real vulnerability is reported to the
 * maintainer privately first, through the repo's security policy or a GitHub
 * private vulnerability report, and only written about after a fix ships or
 * the disclosure window (90 days is the norm) has passed.
 *
 * Usage:
 *   npm run build
 *   node scripts/ecosystem-scan.js                       scan scripts/ecosystem-targets.txt
 *   node scripts/ecosystem-scan.js my-targets.txt        scan another list
 *   node scripts/ecosystem-scan.js --out ./audit-2026-11 choose the report directory
 *   node scripts/ecosystem-scan.js --rules MCP013,MCP014 only these rules
 *
 * Output (in --out, default .ecosystem-audit/, which is gitignored):
 *   report.md    — per-target summary and every default-tier finding with its trace
 *   report.json  — the same, machine-readable
 */
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const here = path.dirname(fileURLToPath(import.meta.url));
const root = path.resolve(here, "..");
const dist = (p) => path.join(root, "dist", p);

if (!fs.existsSync(dist("index.js"))) {
  console.error("dist/ is missing: run `npm run build` first.");
  process.exit(1);
}

const { resolveTarget } = await import(dist("scanner/fetch-target.js"));
const { scanRepositoryDetailed } = await import(dist("scanner/scan.js"));
const { scanKnownMaliciousPackages } = await import(dist("scanner/dependency-guard.js"));

const args = process.argv.slice(2);
const option = (name) => {
  const i = args.indexOf(name);
  return i >= 0 ? args[i + 1] : undefined;
};
const outDir = path.resolve(option("--out") ?? path.join(root, ".ecosystem-audit"));
const rules = option("--rules")?.split(",").map((r) => r.trim().toUpperCase());
const listFile = args.find((a, i) => !a.startsWith("--") && !["--out", "--rules"].includes(args[i - 1]))
  ?? path.join(here, "ecosystem-targets.txt");

const targets = fs
  .readFileSync(listFile, "utf8")
  .split(/\r?\n/)
  .map((line) => line.replace(/#.*/, "").trim())
  .filter(Boolean);

const results = [];
for (const target of targets) {
  const started = Date.now();
  process.stdout.write(`${target} ... `);
  let resolved;
  try {
    resolved = resolveTarget(target);
  } catch (err) {
    console.log(`fetch failed: ${err.message.split("\n")[0]}`);
    results.push({ target, error: err.message.split("\n")[0], findings: [] });
    continue;
  }
  try {
    const scan = scanRepositoryDetailed(resolved.dir, rules ? { rules } : undefined);
    const all = [...scan.findings, ...(rules && !rules.includes("DEP003") ? [] : scanKnownMaliciousPackages(resolved.dir))];
    const findings = all
      .filter((f) => f.evidence !== "heuristic")
      .map((f) => ({ rule: f.rule_id, severity: f.severity, evidence: f.evidence, file: f.file, line: f.line, summary: f.summary, trace: f.trace ?? [] }));
    results.push({ target, label: resolved.label, seconds: Math.round((Date.now() - started) / 1000), findings });
    console.log(`${findings.length} finding(s)`);
  } catch (err) {
    console.log(`scan failed: ${err.message}`);
    results.push({ target, label: resolved.label, error: err.message, findings: [] });
  } finally {
    resolved.cleanup();
  }
}

fs.mkdirSync(outDir, { recursive: true });
const date = new Date().toISOString().slice(0, 10);
fs.writeFileSync(path.join(outDir, "report.json"), JSON.stringify({ date, targets: results }, null, 2) + "\n");

const md = [
  `# Ecosystem audit — ${date}`,
  "",
  "> **Private triage notes. Do not publish as-is.** Read every finding against its source line.",
  "> A false positive is a rule bug: fix the rule and add a `test-fixtures/safe/` fixture.",
  "> A real vulnerability goes to the maintainer privately first (their SECURITY.md, or GitHub",
  "> \"Report a vulnerability\" on the repo's Security tab). Write about it only after a fix ships",
  "> or the disclosure window has passed, and credit the maintainer for fixing it.",
  "",
  "| Target | Scanned | Default-tier findings |",
  "|---|---|---|",
  ...results.map((r) => `| ${r.target} | ${r.error ? `error: ${r.error}` : r.label} | ${r.findings.length} |`),
  "",
];
for (const r of results.filter((x) => x.findings.length > 0)) {
  md.push(`## ${r.target}`, "");
  for (const f of r.findings) {
    md.push(`- **${f.rule}** (${f.severity}, ${f.evidence}) \`${f.file}:${f.line}\`: ${f.summary}`);
    for (const step of f.trace) md.push(`  - ${step.kind} \`${step.file}:${step.line}\` ${step.note}`);
    md.push("  - [ ] read against source · [ ] real → reported privately · [ ] false positive → rule fixed + fixture");
  }
  md.push("");
}
fs.writeFileSync(path.join(outDir, "report.md"), md.join("\n"));
console.log(`\nReport: ${path.join(outDir, "report.md")}`);
