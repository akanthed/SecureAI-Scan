#!/usr/bin/env node
/**
 * Regenerates src/scanner/advisories-generated.ts from the OSV database.
 *
 * Rationale: DEP003 shipped as a two-entry hand-curated list, which is
 * stale-by-construction and could never justify the README's comparison to a
 * real advisory feed. This pulls high/critical advisories for an explicit
 * watchlist of LLM/MCP/RAG packages and bakes them into a snapshot so the
 * runtime check stays fully offline (no network on `scan`), while the data
 * itself is refreshable and citable.
 *
 * Scope discipline (CLAUDE.md §3): the watchlist is LLM/MCP/RAG packages only.
 * Do not add general-purpose libraries here.
 *
 *   node scripts/sync-advisories.js
 */
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const here = path.dirname(fileURLToPath(import.meta.url));
const OUT = path.resolve(here, "..", "src", "scanner", "advisories-generated.ts");

const WATCHLIST = [
  // ── MCP ──
  ["npm", "@modelcontextprotocol/sdk"],
  ["npm", "@modelcontextprotocol/inspector"],
  ["npm", "mcp-remote"],
  ["npm", "mcp-proxy"],
  ["npm", "fastmcp"],
  ["PyPI", "mcp"],
  ["PyPI", "fastmcp"],
  ["PyPI", "mcp-server-git"],
  ["PyPI", "mcp-server-fetch"],
  // ── LLM SDKs / gateways ──
  ["npm", "openai"],
  ["npm", "@anthropic-ai/sdk"],
  ["npm", "ai"],
  ["npm", "@google/genai"],
  ["npm", "@google/generative-ai"],
  ["npm", "@mistralai/mistralai"],
  ["npm", "cohere-ai"],
  ["npm", "ollama"],
  ["npm", "@huggingface/inference"],
  ["PyPI", "openai"],
  ["PyPI", "anthropic"],
  ["PyPI", "litellm"],
  ["PyPI", "google-generativeai"],
  ["PyPI", "mistralai"],
  ["PyPI", "cohere"],
  ["PyPI", "ollama"],
  ["PyPI", "llama-cpp-python"],
  ["PyPI", "transformers"],
  ["PyPI", "vllm"],
  // ── Agent / RAG frameworks ──
  ["npm", "langchain"],
  ["npm", "@langchain/core"],
  ["npm", "@langchain/community"],
  ["npm", "llamaindex"],
  ["PyPI", "langchain"],
  ["PyPI", "langchain-core"],
  ["PyPI", "langchain-community"],
  ["PyPI", "langchain-experimental"],
  ["PyPI", "llama-index"],
  ["PyPI", "llama-index-core"],
  ["PyPI", "haystack-ai"],
  ["PyPI", "crewai"],
  ["PyPI", "autogen-agentchat"],
  ["PyPI", "langflow"],
  ["PyPI", "gradio"],
  // ── Vector stores ──
  ["PyPI", "chromadb"],
  ["PyPI", "qdrant-client"],
  ["PyPI", "weaviate-client"],
  ["PyPI", "pymilvus"],
  ["npm", "chromadb"],
];

/** Only advisories at this bar become `proven`-tier DEP003 findings. */
const ACCEPTED_SEVERITIES = new Set(["HIGH", "CRITICAL"]);

function severityOf(vuln) {
  const dbs = vuln.database_specific?.severity;
  if (dbs) return String(dbs).toUpperCase();
  for (const s of vuln.severity ?? []) {
    const m = /CVSS:3\.[01]\/.*/.exec(s.score ?? "");
    if (m) return "UNKNOWN";
  }
  return "UNKNOWN";
}

/**
 * OSV `ranges` → comparator strings this scanner's semver.ts understands.
 * `introduced: "0"` is dropped (unbounded below); `fixed`/`last_affected`
 * become `<`/`<=`. A range whose bounds aren't exact `x.y.z` is dropped
 * entirely rather than emitted half-parsed — a partial range would silently
 * clear versions it shouldn't.
 */
function rangesFor(vuln, ecosystem, name) {
  const out = [];
  for (const affected of vuln.affected ?? []) {
    if (affected.package?.ecosystem !== ecosystem) continue;
    if (normalize(ecosystem, affected.package?.name ?? "") !== normalize(ecosystem, name)) continue;
    for (const range of affected.ranges ?? []) {
      if (range.type !== "ECOSYSTEM" && range.type !== "SEMVER") continue;
      let introduced;
      const comparators = [];
      let usable = true;
      for (const event of range.events ?? []) {
        if (event.introduced !== undefined) {
          introduced = event.introduced;
          if (introduced !== "0") {
            if (!isExact(introduced)) usable = false;
            else comparators.push(`>=${introduced}`);
          }
        } else if (event.fixed !== undefined) {
          if (!isExact(event.fixed)) usable = false;
          else comparators.push(`<${event.fixed}`);
        } else if (event.last_affected !== undefined) {
          if (!isExact(event.last_affected)) usable = false;
          else comparators.push(`<=${event.last_affected}`);
        }
      }
      if (usable && comparators.length > 0) out.push(comparators.join(" "));
    }
  }
  return [...new Set(out)];
}

function isExact(v) {
  return /^v?\d+\.\d+\.\d+$/.test(String(v).trim());
}

function normalize(ecosystem, name) {
  const lower = name.toLowerCase();
  return ecosystem === "PyPI" ? lower.replace(/[-_.]+/g, "-") : lower;
}

function cveOf(vuln) {
  return (vuln.aliases ?? []).find((a) => a.startsWith("CVE-")) ?? vuln.id;
}

async function query(ecosystem, name) {
  const res = await fetch("https://api.osv.dev/v1/query", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ package: { ecosystem, name } }),
  });
  if (!res.ok) throw new Error(`OSV ${res.status} for ${ecosystem}/${name}`);
  const json = await res.json();
  return json.vulns ?? [];
}

const entries = [];
let skippedNoRange = 0;

for (const [ecosystem, name] of WATCHLIST) {
  let vulns;
  try {
    vulns = await query(ecosystem, name);
  } catch (err) {
    console.error(`  ! ${ecosystem}/${name}: ${err.message}`);
    continue;
  }
  const seen = new Set();
  let kept = 0;
  for (const vuln of vulns) {
    if (vuln.withdrawn) continue;
    if (!ACCEPTED_SEVERITIES.has(severityOf(vuln))) continue;
    const cve = cveOf(vuln);
    if (seen.has(cve)) continue;
    const ranges = rangesFor(vuln, ecosystem, name);
    if (ranges.length === 0) {
      skippedNoRange += 1;
      continue;
    }
    seen.add(cve);
    kept += 1;
    entries.push({
      ecosystem: ecosystem === "PyPI" ? "pypi" : "npm",
      name: normalize(ecosystem, name),
      kind: "vulnerable",
      ranges,
      affectedVersions: ranges.join(" || "),
      reason: `${cve}: ${String(vuln.summary ?? vuln.details ?? "").replace(/\s+/g, " ").trim().slice(0, 220)}`,
      reference: `https://osv.dev/vulnerability/${vuln.id}`,
    });
  }
  console.log(`  ${ecosystem}/${name}: ${kept} advisory(s) from ${vulns.length} record(s)`);
}

entries.sort((a, b) =>
  a.ecosystem === b.ecosystem
    ? a.name === b.name
      ? a.reason.localeCompare(b.reason)
      : a.name.localeCompare(b.name)
    : a.ecosystem.localeCompare(b.ecosystem),
);

const banner = `/**
 * GENERATED FILE — do not edit by hand.
 * Regenerate with: node scripts/sync-advisories.js
 *
 * Snapshot of HIGH/CRITICAL OSV advisories for the LLM/MCP/RAG package
 * watchlist in that script. Bundled so DEP003 stays fully offline at scan
 * time. Only advisories with a machine-comparable exact version range are
 * included — an advisory whose range can't be parsed is dropped rather than
 * shipped as an always-on finding.
 *
 * Synced: ${new Date().toISOString().slice(0, 10)}
 */
import type { PackageAdvisory } from "./advisories.js";

export const GENERATED_ADVISORIES: PackageAdvisory[] = ${JSON.stringify(entries, null, 2)};
`;

fs.writeFileSync(OUT, banner);
console.log(
  `\nWrote ${entries.length} advisories to ${path.relative(process.cwd(), OUT)} (${skippedNoRange} skipped: no parseable range)`,
);
