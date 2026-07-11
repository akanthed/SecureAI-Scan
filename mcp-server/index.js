#!/usr/bin/env node
/**
 * SecureAI-Scan MCP Server
 *
 * Exposes three tools to Claude (and any MCP-compatible LLM host):
 *   - scan_repository — scan a local path, return findings with evidence tiers
 *   - explain_rule    — return rule explanation with OWASP mapping
 *   - generate_bom    — AI Bill of Materials for a repository
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
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const distRoot = path.resolve(__dirname, "..", "dist");

// Dynamic imports from compiled dist
const { scanRepositoryDetailed } = await import(`${distRoot}/scanner/scan.js`);
const { filterFindingsBySeverity } = await import(`${distRoot}/scanner/filters.js`);
const { StaticExplainer } = await import(`${distRoot}/scanner/explainer.js`);
const { catalogFor } = await import(`${distRoot}/scanner/catalog.js`);
const { generateBom } = await import(`${distRoot}/scanner/bom.js`);
const { AVAILABLE_RULE_IDS } = await import(`${distRoot}/scanner/rules/index.js`);

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
      "Scan a local repository for AI/LLM security vulnerabilities with evidence-tiered findings (proven/likely/heuristic). Detects prompt injection (with source→sink dataflow traces), MCP supply-chain issues, RAG data poisoning, and agent trust violations in TypeScript/JS, Python, and MCP config files.",
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
