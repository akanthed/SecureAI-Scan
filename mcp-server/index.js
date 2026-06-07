#!/usr/bin/env node
/**
 * SecureAI-Scan MCP Server
 *
 * Exposes three tools to Claude (and any MCP-compatible LLM host):
 *   • scan_repository   — scan a local path, return findings as JSON
 *   • explain_rule      — return rule explanation
 *   • evaluate_prompt   — evaluate raw prompt text for injection risk
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
 * Or in a project .mcp.json:
 *   {
 *     "mcpServers": {
 *       "secureai-scan": {
 *         "command": "node",
 *         "args": ["./mcp-server/index.js"]
 *       }
 *     }
 *   }
 *
 * Requires: npm run build (in the secureai-scan root) first.
 */

import { createRequire } from "node:module";
import readline from "node:readline";
import path from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const distRoot = path.resolve(__dirname, "..", "dist");

// Dynamic imports from compiled dist
const { scanRepositoryDetailed } = await import(`${distRoot}/scanner/scan.js`);
const { filterFindingsBySeverity } = await import(`${distRoot}/scanner/filters.js`);
const { StaticExplainer } = await import(`${distRoot}/scanner/explainer.js`);
const { evaluatePromptRisk } = await import(`${distRoot}/scanner/prompt-risk.js`);
const { AVAILABLE_RULE_IDS } = await import(`${distRoot}/scanner/rules/index.js`);

// ── Tool definitions ──────────────────────────────────────────────────────

const TOOLS = [
  {
    name: "scan_repository",
    description:
      "Scan a local repository for AI/LLM security vulnerabilities. Detects prompt injection, MCP tool poisoning, RAG data poisoning, agent trust boundary violations, and 19 more rules (TypeScript/JS + Python). Returns structured findings.",
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
        min_confidence: {
          type: "number",
          description: "Minimum confidence threshold 0–1 (default: 0.4).",
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
      "Return a detailed explanation for any SecureAI-Scan rule: why it's dangerous, how attackers exploit it, and how to fix it with a code example.",
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
    name: "evaluate_prompt",
    description:
      "Evaluate raw prompt text for injection risk patterns (instruction override, jailbreak phrases, role confusion). Returns a risk level and mitigations.",
    inputSchema: {
      type: "object",
      properties: {
        text: {
          type: "string",
          description: "The prompt text to evaluate.",
        },
      },
      required: ["text"],
    },
  },
];

// ── Handlers ──────────────────────────────────────────────────────────────

function handleScanRepository(args) {
  const targetPath = args.path;
  if (!targetPath) throw new Error("'path' is required.");

  const minSeverity = args.min_severity ?? undefined;
  const minConfidence = args.min_confidence ?? 0.4;
  const rules = args.rules ?? undefined;
  const limit = args.limit ?? 50;

  let scanResult;
  try {
    scanResult = scanRepositoryDetailed(targetPath, { rules });
  } catch (err) {
    throw new Error(`Scan failed: ${err?.message ?? String(err)}`);
  }

  const filtered = filterFindingsBySeverity(
    scanResult.findings.filter((f) => f.confidence >= minConfidence),
    minSeverity,
  );

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
    confidence: Math.round(f.confidence * 100),
    file: f.file,
    line: f.line,
    summary: f.summary,
    recommendation: f.recommendation,
  }));

  return {
    scanned_ts_files: scanResult.scannedFiles.length,
    scanned_python_files: (scanResult.pythonFiles ?? []).length,
    total_findings: filtered.length,
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
  const explainer = new StaticExplainer();
  const exp = explainer.explain({
    rule_id: normalized, title: normalized, severity: "medium",
    file: "", line: 0, summary: "", description: "", recommendation: "", confidence: 0,
  });
  return {
    rule_id: normalized,
    summary: exp.summary,
    why_risky: exp.whyRisky,
    how_exploited: exp.howExploited,
    how_to_fix: exp.howToFix,
    code_example: exp.codeExample,
  };
}

function handleEvaluatePrompt(args) {
  const text = args.text;
  if (!text) throw new Error("'text' is required.");
  const result = evaluatePromptRisk(text);
  return { risk_level: result.level, reasons: result.reasons, suggestions: result.suggestions };
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
        serverInfo: { name: "secureai-scan", version: "0.2.1" },
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
      else if (toolName === "evaluate_prompt") result = handleEvaluatePrompt(args);
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
