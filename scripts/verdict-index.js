#!/usr/bin/env node
/**
 * Verdict index: runs `secureai-scan mcp`/`skill` (the "verify before you
 * install" path) against a curated list of public MCP servers and Agent
 * Skills, and writes a dated markdown table of the result — a linkable,
 * citable artifact instead of a private one-off scan.
 *
 * TARGETS below are real, vendor-published packages/repos, verified to exist
 * (npm registry 200, or GitHub repo 200) before being added here — not pulled
 * from an unvetted "awesome list". Naming a third-party package in a public
 * "safe/flagged" table is a public claim about someone else's project: every
 * finding must be read by hand before this index is trusted or published
 * (same bar as test/regression-baseline.json), and adding a new entry means
 * re-verifying it exists the same way.
 *
 * Usage:
 *   node scripts/verdict-index.js                 scan TARGETS, write docs/verdict-index.md
 *   node scripts/verdict-index.js --paranoid       include heuristic-tier findings
 */
import { execFileSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const here = path.dirname(fileURLToPath(import.meta.url));
const root = path.resolve(here, "..");
const cliPath = path.join(root, "dist", "index.js");
const outPath = path.join(root, "docs", "verdict-index.md");
const paranoid = process.argv.includes("--paranoid");

const TARGETS = [
  { kind: "mcp", name: "@modelcontextprotocol/server-filesystem", label: "MCP: filesystem (official reference server)" },
  { kind: "mcp", name: "@modelcontextprotocol/server-everything", label: "MCP: everything (official reference server)" },
  { kind: "mcp", name: "@modelcontextprotocol/server-memory", label: "MCP: memory (official reference server)" },
  { kind: "mcp", name: "@modelcontextprotocol/server-sequential-thinking", label: "MCP: sequential-thinking (official reference server)" },
  { kind: "mcp", name: "@modelcontextprotocol/server-brave-search", label: "MCP: brave-search (official reference server)" },
  { kind: "mcp", name: "@modelcontextprotocol/server-puppeteer", label: "MCP: puppeteer (official reference server)" },
  { kind: "mcp", name: "@modelcontextprotocol/server-postgres", label: "MCP: postgres (official reference server)" },
  { kind: "mcp", name: "@modelcontextprotocol/server-github", label: "MCP: github (official reference server)" },
  { kind: "mcp", name: "@modelcontextprotocol/server-gitlab", label: "MCP: gitlab (official reference server)" },
  { kind: "mcp", name: "@modelcontextprotocol/server-slack", label: "MCP: slack (official reference server)" },
  { kind: "mcp", name: "@modelcontextprotocol/server-google-maps", label: "MCP: google-maps (official reference server)" },
  { kind: "mcp", name: "@modelcontextprotocol/server-redis", label: "MCP: redis (official reference server)" },
  { kind: "mcp", name: "@modelcontextprotocol/server-everart", label: "MCP: everart (official reference server)" },
  { kind: "mcp", name: "@playwright/mcp", label: "MCP: Playwright (Microsoft)" },
  { kind: "mcp", name: "@upstash/context7-mcp", label: "MCP: Context7 (Upstash)" },
  { kind: "mcp", name: "@notionhq/notion-mcp-server", label: "MCP: Notion (official)" },
  { kind: "mcp", name: "firecrawl-mcp", label: "MCP: Firecrawl (official)" },
  { kind: "mcp", name: "@supabase/mcp-server-supabase", label: "MCP: Supabase (official)" },
  { kind: "mcp", name: "@cloudflare/mcp-server-cloudflare", label: "MCP: Cloudflare (official)" },
  { kind: "mcp", name: "@sentry/mcp-server", label: "MCP: Sentry (official)" },
  { kind: "mcp", name: "zencoderai/slack-mcp-server", label: "MCP: slack-mcp-server (Zencoder, GitHub)" },
  { kind: "mcp", name: "sooperset/mcp-atlassian", label: "MCP: mcp-atlassian (GitHub)" },
  { kind: "skill", name: "anthropics/skills", label: "Agent Skills: anthropics/skills (official corpus)" },
];

function scanTarget(target) {
  const args = [cliPath, target.kind, target.name, "--output", "-"];
  if (paranoid) args.push("--paranoid");
  let json;
  try {
    // --output - isn't supported; write to a temp file instead.
    const tmpFile = path.join(root, `.verdict-tmp-${target.kind}.json`);
    execFileSync(
      process.execPath,
      [cliPath, target.kind, target.name, "--output", tmpFile, ...(paranoid ? ["--paranoid"] : [])],
      { cwd: root, stdio: ["ignore", "ignore", "pipe"] },
    );
    json = JSON.parse(fs.readFileSync(tmpFile, "utf-8"));
    fs.rmSync(tmpFile, { force: true });
  } catch (err) {
    return { target, error: (err.stderr ?? err.message ?? String(err)).toString().trim() };
  }
  return { target, report: json };
}

function verdictLine({ target, report, error }) {
  if (error) {
    return `| ${target.label} | ⚠️ scan failed | — | \`${error.slice(0, 120)}\` |`;
  }
  const s = report.summary;
  if (s.total === 0) {
    return `| ${target.label} | ✅ clean | 0 | no proven/likely findings |`;
  }
  const top = report.groups
    .slice(0, 3)
    .map((g) => `${g.ruleId} (${g.severity})`)
    .join(", ");
  return `| ${target.label} | ⚠️ ${s.total} finding(s) | ${s.total} | ${top} |`;
}

const results = TARGETS.map(scanTarget);

const lines = [
  "# SecureAI-Scan verdict index",
  "",
  `Scanned ${new Date().toISOString()} with \`secureai-scan mcp\`/\`skill\` (evidence-gated: proven + likely only${paranoid ? ", plus heuristic (--paranoid)" : ""}).`,
  "",
  "Each row is a real scan of the published package/repo, not a claim reviewed line-by-line here — read the full report (`--output`) before trusting a ⚠️ row as a verdict, the same way `test/regression-baseline.json` findings are hand-reviewed before being accepted.",
  "",
  "| Target | Verdict | Findings | Top rule(s) |",
  "|---|---|---:|---|",
  ...results.map(verdictLine),
  "",
];

fs.mkdirSync(path.dirname(outPath), { recursive: true });
fs.writeFileSync(outPath, lines.join("\n"));
process.stdout.write(lines.join("\n") + "\n");
process.stdout.write(`\nWritten to ${path.relative(root, outPath)}\n`);
