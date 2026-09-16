#!/usr/bin/env node
/**
 * SecureAI-Scan MCP Server
 *
 * Exposes four tools to Claude (and any MCP-compatible LLM host):
 *   - scan_repository       — scan a local path, return findings with evidence tiers
 *   - explain_rule          — return rule explanation with OWASP mapping
 *   - generate_bom          — AI Bill of Materials for a repository
 *   - scan_untrusted_target — fetch and scan a skill/MCP server BEFORE installing it
 *
 * scan_untrusted_target is the pre-install wedge from inside the agent
 * itself: when Claude is about to recommend or install a skill or MCP
 * server, it can scan the target first — no clone, no config, nothing
 * fetched is ever executed. Same fetch-target.ts used by the `secureai-scan
 * skill`/`secureai-scan mcp` CLI commands.
 *
 * Register in claude_desktop_config.json:
 *   {
 *     "mcpServers": {
 *       "secureai-scan": {
 *         "command": "node",
 *         "args": ["/absolute/path/to/secureai-scan/mcp-server/index.js"]
 *       }
 *     }
 *   }
 *
 * Requires: npm run build (in the secureai-scan root) first.
 */

import fs from "node:fs";
import readline from "node:readline";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const distRoot = path.resolve(__dirname, "..", "dist");

// Dynamic imports from compiled dist. A raw Windows path ("D:\...") is not a
// valid specifier for import() — Node's ESM loader requires a file:// URL
// for absolute paths, and throws ERR_UNSUPPORTED_ESM_URL_SCHEME otherwise.
// Wrapping every dist import in pathToFileURL is what makes this server
// startable on Windows at all (it previously failed on the very first
// import, before any tool could run).
const distImport = (relPath) => import(pathToFileURL(path.join(distRoot, relPath)).href);

const { scanRepositoryDetailed } = await distImport("scanner/scan.js");
const { filterFindingsBySeverity } = await distImport("scanner/filters.js");
const { StaticExplainer } = await distImport("scanner/explainer.js");
const { catalogFor } = await distImport("scanner/catalog.js");
const { generateBom } = await distImport("scanner/bom.js");
const { AVAILABLE_RULE_IDS } = await distImport("scanner/rules/index.js");
const { resolveTarget } = await distImport("scanner/fetch-target.js");
const { scanSkillFiles, findSkillFiles } = await distImport("scanner/skill-scanner.js");
const { scanKnownMaliciousPackages } = await distImport("scanner/dependency-guard.js");

const OWN_VERSION = (() => {
  try {
    return JSON.parse(fs.readFileSync(path.resolve(__dirname, "..", "package.json"), "utf-8")).version ?? "0.0.0";
  } catch {
    return "0.0.0";
  }
})();

// ── Tool definitions ──────────────────────────────────────────────────────

const TOOLS = [
  {
    name: "scan_repository",
    description:
      "Scan a local repository for AI/LLM security vulnerabilities with evidence-tiered findings (proven/likely/heuristic). Detects prompt injection (with source→sink dataflow traces), MCP supply-chain issues, RAG data poisoning, and agent trust violations in TypeScript/JS, Python, and MCP config files. Use for requests like 'scan my MCP config', 'check this repo for prompt injection risk', or any AI/LLM security review of local code.",
    inputSchema: {
      type: "object",
      properties: {
        path: {
          type: "string",
          description: "Absolute or relative path to the repository root to scan.",
        },
        min_severity: {
          type: "string",
          enum: ["low", "medium", "high", "critical"],
          description: "Minimum severity to return (default: low).",
        },
        paranoid: {
          type: "boolean",
          description: "Include heuristic-tier findings (default: false — only proven/likely).",
        },
        rules: {
          type: "array",
          items: { type: "string" },
          description: `Limit to specific rule IDs. Available: ${AVAILABLE_RULE_IDS.join(", ")}`,
        },
        limit: {
          type: "number",
          description: "Max findings to return (default: 50).",
        },
      },
      required: ["path"],
    },
  },
  {
    name: "explain_rule",
    description:
      "Return a detailed explanation for any SecureAI-Scan rule: OWASP LLM Top 10 mapping, why it's dangerous, how attackers exploit it, and how to fix it with a code example.",
    inputSchema: {
      type: "object",
      properties: {
        rule_id: {
          type: "string",
          description: `Rule ID to explain. Available: ${AVAILABLE_RULE_IDS.join(", ")}`,
        },
      },
      required: ["rule_id"],
    },
  },
  {
    name: "generate_bom",
    description:
      "Generate an AI Bill of Materials for a repository: LLM provider SDKs, model identifiers, vector stores, agent frameworks, embedding models, and MCP servers, with the files where each was found.",
    inputSchema: {
      type: "object",
      properties: {
        path: {
          type: "string",
          description: "Absolute or relative path to the repository root.",
        },
      },
      required: ["path"],
    },
  },
  {
    name: "scan_untrusted_target",
    description:
      "Fetch and scan a single Agent Skill or MCP server BEFORE it is trusted/installed — no repo, no config. Accepts a local path, a git URL, a GitHub \"owner/repo\" shorthand, or (for MCP servers) a bare npm package name. Nothing fetched is ever executed: npm targets are downloaded with 'npm pack' (tarball only, no install, no lifecycle scripts), git targets with 'git clone --depth 1'. Use this before recommending or installing any third-party skill or MCP server, or whenever the user asks 'is this skill safe?', 'is this MCP server safe to install?', or wants a third-party skill/MCP server checked before trusting it.",
    inputSchema: {
      type: "object",
      properties: {
        target: {
          type: "string",
          description: "Local path, git URL, \"owner/repo\", or npm package name to fetch and scan.",
        },
        kind: {
          type: "string",
          enum: ["skill", "mcp"],
          description: "'skill' scans only for Agent Skill poisoning/evasion (SKL001-005). 'mcp' runs the full rule set plus DEP003 advisories, appropriate for an MCP server package.",
        },
        paranoid: {
          type: "boolean",
          description: "Include heuristic-tier findings (default: false — only proven/likely).",
        },
      },
      required: ["target", "kind"],
    },
  },
];

// ── Handlers ──────────────────────────────────────────────────────────────

function handleScanRepository(args) {
  const targetPath = args.path;
  if (!targetPath) throw new Error("'path' is required.");

  const minSeverity = args.min_severity ?? undefined;
  const paranoid = args.paranoid ?? false;
  const rules = args.rules ?? undefined;
  const limit = args.limit ?? 50;

  let scanResult;
  try {
    scanResult = scanRepositoryDetailed(targetPath, { rules });
  } catch (err) {
    throw new Error(`Scan failed: ${err?.message ?? String(err)}`);
  }

  const evidenceFiltered = paranoid
    ? scanResult.findings
    : scanResult.findings.filter((f) => f.evidence !== "heuristic");
  const filtered = filterFindingsBySeverity(evidenceFiltered, minSeverity);

  const bySeverity = {
    critical: filtered.filter((f) => f.severity === "critical").length,
    high: filtered.filter((f) => f.severity === "high").length,
    medium: filtered.filter((f) => f.severity === "medium").length,
    low: filtered.filter((f) => f.severity === "low").length,
  };

  const findings = filtered.slice(0, limit).map((f) => ({
    rule_id: f.rule_id,
    title: f.title,
    severity: f.severity,
    evidence: f.evidence,
    owasp: catalogFor(f.rule_id)?.owasp,
    file: f.file,
    line: f.line,
    summary: f.summary,
    trace: f.trace,
    recommendation: f.recommendation,
  }));

  return {
    scanned_ts_files: scanResult.scannedFiles.length,
    scanned_python_files: (scanResult.pythonFiles ?? []).length,
    total_findings: filtered.length,
    hidden_heuristic: scanResult.findings.length - evidenceFiltered.length,
    shown: findings.length,
    by_severity: bySeverity,
    findings,
    ignored: scanResult.ignoredFindings.length,
    ...(filtered.length > limit
      ? { note: `${filtered.length - limit} more findings. Increase 'limit' to see them.` }
      : {}),
  };
}

function handleExplainRule(args) {
  const ruleId = args.rule_id;
  if (!ruleId) throw new Error("'rule_id' is required.");
  const normalized = String(ruleId).trim().toUpperCase();
  if (!AVAILABLE_RULE_IDS.includes(normalized)) {
    throw new Error(`Unknown rule ID "${normalized}". Available: ${AVAILABLE_RULE_IDS.join(", ")}`);
  }
  const catalog = catalogFor(normalized);
  const explainer = new StaticExplainer();
  const exp = explainer.explain({
    rule_id: normalized, title: normalized, severity: "medium",
    file: "", line: 0, summary: "", description: "", recommendation: "",
    confidence: 0, evidence: "likely",
  });
  return {
    rule_id: normalized,
    title: catalog?.title,
    severity: catalog?.severity,
    owasp: catalog ? `${catalog.owasp} (${catalog.owaspName})` : undefined,
    eu_ai_act: catalog?.euAiAct,
    summary: exp.summary,
    why_risky: exp.whyRisky,
    how_exploited: exp.howExploited,
    how_to_fix: exp.howToFix,
    code_example: exp.codeExample,
  };
}

function handleGenerateBom(args) {
  const targetPath = args.path;
  if (!targetPath) throw new Error("'path' is required.");
  return generateBom(targetPath);
}

function handleScanUntrustedTarget(args) {
  const target = args.target;
  const kind = args.kind;
  if (!target) throw new Error("'target' is required.");
  if (kind !== "skill" && kind !== "mcp") throw new Error("'kind' must be 'skill' or 'mcp'.");
  const paranoid = args.paranoid ?? false;

  let resolved;
  try {
    resolved = resolveTarget(target);
  } catch (err) {
    throw new Error(`Could not fetch "${target}": ${err?.message ?? String(err)}`);
  }

  try {
    let findings;
    if (kind === "skill") {
      if (findSkillFiles(resolved.dir).length === 0) {
        return { target: resolved.label, kind, fetched_as: resolved.kind, note: "No SKILL.md found under this target — nothing to scan." };
      }
      findings = scanSkillFiles(resolved.dir);
    } else {
      const scanResult = scanRepositoryDetailed(resolved.dir);
      findings = [...scanResult.findings, ...scanKnownMaliciousPackages(resolved.dir)];
    }

    const evidenceFiltered = paranoid ? findings : findings.filter((f) => f.evidence !== "heuristic");

    return {
      target: resolved.label,
      kind,
      fetched_as: resolved.kind,
      executed_anything: false,
      total_findings: evidenceFiltered.length,
      hidden_heuristic: findings.length - evidenceFiltered.length,
      findings: evidenceFiltered.map((f) => ({
        rule_id: f.rule_id,
        title: f.title,
        severity: f.severity,
        evidence: f.evidence,
        owasp: catalogFor(f.rule_id)?.owasp,
        file: f.file,
        line: f.line,
        summary: f.summary,
        trace: f.trace,
        recommendation: f.recommendation,
      })),
    };
  } finally {
    resolved.cleanup();
  }
}

// ── JSON-RPC dispatcher ───────────────────────────────────────────────────

function send(obj) {
  process.stdout.write(JSON.stringify(obj) + "\n");
}

function errResp(id, code, message) {
  return { jsonrpc: "2.0", id: id ?? null, error: { code, message } };
}

function dispatch(req) {
  const id = req.id ?? null;

  if (req.method === "initialize") {
    send({
      jsonrpc: "2.0", id,
      result: {
        protocolVersion: "2024-11-05",
        serverInfo: { name: "secureai-scan", version: OWN_VERSION },
        capabilities: { tools: {} },
      },
    });
    return;
  }

  if (req.method === "notifications/initialized") return;

  if (req.method === "tools/list") {
    send({ jsonrpc: "2.0", id, result: { tools: TOOLS } });
    return;
  }

  if (req.method === "tools/call") {
    const toolName = req.params?.name;
    const args = req.params?.arguments ?? {};
    try {
      let result;
      if (toolName === "scan_repository") result = handleScanRepository(args);
      else if (toolName === "explain_rule") result = handleExplainRule(args);
      else if (toolName === "generate_bom") result = handleGenerateBom(args);
      else if (toolName === "scan_untrusted_target") result = handleScanUntrustedTarget(args);
      else { send(errResp(id, -32601, `Unknown tool: "${toolName}"`)); return; }

      send({
        jsonrpc: "2.0", id,
        result: { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] },
      });
    } catch (err) {
      send(errResp(id, -32603, err?.message ?? String(err)));
    }
    return;
  }

  if (req.id == null) return; // notification
  send(errResp(id, -32601, `Method not found: ${req.method}`));
}

// ── Stdio transport ───────────────────────────────────────────────────────

const rl = readline.createInterface({ input: process.stdin, crlfDelay: Infinity });

rl.on("line", (raw) => {
  const line = raw.trim();
  if (!line) return;
  let req;
  try { req = JSON.parse(line); } catch {
    send(errResp(null, -32700, "Parse error: invalid JSON"));
    return;
  }
  dispatch(req);
});
