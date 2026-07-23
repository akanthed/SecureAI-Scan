import fs from "node:fs";
import path from "node:path";
import type { Finding, Severity } from "./types.js";
import { evidenceConfidence, demoteEvidence } from "./confidence.js";
import {
  findCrossToolReference,
  findInvisibleUnicode,
  matchInjectionPhrases,
} from "./tool-poisoning-checks.js";

// ── Python LLM SDK call patterns ──────────────────────────────────────────
const LLM_CALL_PATTERNS = [
  /openai\s*\.\s*chat\s*\.\s*completions\s*\.\s*create/,
  /client\s*\.\s*chat\s*\.\s*completions\s*\.\s*create/,
  /openai\s*\.\s*ChatCompletion\s*\.\s*create/,
  /anthropic\s*\.\s*messages\s*\.\s*create/,
  /client\s*\.\s*messages\s*\.\s*create/,
  /genai\s*\.\s*generate_content/,
  /model\s*\.\s*generate_content/,
  /\.\s*invoke_model\s*\(/,
  /\.\s*converse\s*\(/,
  /llm\s*\.\s*invoke\s*\(/,
  /llm\s*\.\s*predict\s*\(/,
  /chain\s*\.\s*invoke\s*\(/,
  /chain\s*\.\s*run\s*\(/,
  /ChatOpenAI|ChatAnthropic|ChatGoogleGenerativeAI/,
  /query_engine\s*\.\s*query\s*\(/,
  // litellm: unified gateway, imported/detected separately but its own call
  // syntax was previously absent here, causing a total detection blackout
  // for every litellm-based app.
  /litellm\s*\.\s*(completion|acompletion|text_completion)\s*\(/,
  /co\s*\.\s*chat\s*\(/,
  /cohere_client\s*\.\s*chat\s*\(/,
  /\.\s*chat\s*\.\s*complete\s*\(/,
  /ollama\s*\.\s*(chat|generate)\s*\(/,
];

// ── User input taint sources ───────────────────────────────────────────────
// NOTE: os.environ deliberately excluded — env vars are operator-controlled
// config, not user input. Including them flagged `api_key = os.environ.get(...)`
// next to every LLM client construction as "prompt injection".
const REQUEST_PATTERNS = [
  /request\s*\.\s*(json|form|args|data|values|get_json|files)/,
  /body\s*\[\s*['"]/,
];

// ── Vector store patterns ─────────────────────────────────────────────────
const VECTOR_SEARCH_PATTERNS = [
  /\.\s*similarity_search\s*\(/,
  /\.\s*similarity_search_with_score\s*\(/,
  /\.\s*max_marginal_relevance_search\s*\(/,
  /\.\s*as_retriever\s*\(/,
  /index\s*\.\s*query\s*\(/,
  /collection\s*\.\s*query\s*\(/,
  /\.\s*search\s*\(\s*[^)]*vector/i,
];

const VECTOR_INGEST_PATTERNS = [
  /\.\s*add_documents\s*\(/,
  /\.\s*add_texts\s*\(/,
  /\.\s*from_documents\s*\(/,
  /\.\s*from_texts\s*\(/,
  /\.\s*upsert\s*\(/,
  /\.\s*insert\s*\(/,
];

// ── Dangerous execution sinks ─────────────────────────────────────────────
const EXEC_SINKS = [
  { pattern: /\beval\s*\(/, label: "eval()" },
  { pattern: /\bexec\s*\(/, label: "exec()" },
  { pattern: /subprocess\s*\.\s*(run|call|Popen|check_output)\s*\(/, label: "subprocess" },
  { pattern: /os\s*\.\s*system\s*\(/, label: "os.system()" },
  { pattern: /\bcursor\s*\.\s*execute\s*\(/, label: "cursor.execute() — potential SQL injection" },
];

// ── LLM variable name patterns ────────────────────────────────────────────
const LLM_RESULT_VAR_PATTERNS = [
  /\b(response|completion|result|output|answer|reply|generated|llm_result|chat_result)\b/,
];

// ── LLM SDK import detection ──────────────────────────────────────────────
// Mirrors the TS scanner's fileImportsLlmSdk (llm-rule-utils.ts): name-only
// heuristics like "a variable called `result` reached subprocess.run()" fire
// constantly on ordinary shell-outs (ffmpeg, pip, etc.) in files that have
// nothing to do with LLMs. Gate those heuristics on the file actually
// importing a known LLM SDK first.
const PY_LLM_IMPORT_PATTERNS = [
  /^\s*(?:import|from)\s+openai\b/m,
  /^\s*(?:import|from)\s+anthropic\b/m,
  /^\s*(?:import|from)\s+google\.generativeai\b/m,
  /^\s*(?:import|from)\s+google\.genai\b/m,
  /^\s*(?:import|from)\s+langchain(?:[\w.]*)\b/m,
  /^\s*(?:import|from)\s+litellm\b/m,
  /^\s*(?:import|from)\s+cohere\b/m,
  /^\s*(?:import|from)\s+mistralai\b/m,
  /^\s*(?:import|from)\s+ollama\b/m,
  /^\s*(?:import|from)\s+boto3\b/m,
  /^\s*(?:import|from)\s+llama_index\b/m,
  /^\s*(?:import|from)\s+vertexai\b/m,
];

function fileImportsLlmSdk(raw: string): boolean {
  return PY_LLM_IMPORT_PATTERNS.some((p) => p.test(raw));
}

// ── MCP server SDK import detection (FastMCP / official mcp package) ──────
const PY_MCP_IMPORT_PATTERNS = [
  /^\s*(?:import|from)\s+mcp\b/m,
  /^\s*(?:import|from)\s+fastmcp\b/m,
];

function fileImportsMcpServerSdk(raw: string): boolean {
  return PY_MCP_IMPORT_PATTERNS.some((p) => p.test(raw));
}

// ── MCP tool decorator extraction ─────────────────────────────────────────

const PY_TOOL_DECORATOR_RE = /^\s*@[\w.]*\.tool\b/;

interface PyToolDefinition {
  name: string;
  /** description= kwarg text and/or the decorated function's docstring. */
  texts: Array<{ value: string; line: number }>;
}

/**
 * If lines[i] is an @xxx.tool decorator, extract the tool's name and its
 * descriptive text (a description="..." kwarg on the decorator, plus the
 * docstring of the decorated def). Line numbers are 0-based indices.
 */
function extractPyToolAtLine(lines: string[], i: number): PyToolDefinition | undefined {
  if (!PY_TOOL_DECORATOR_RE.test(lines[i])) return undefined;

  const texts: PyToolDefinition["texts"] = [];
  let name: string | undefined;

  // description= / name= kwargs can span the decorator's argument lines.
  for (let j = i; j < Math.min(lines.length, i + 6); j++) {
    const descMatch = /description\s*=\s*(?:"""|''')?["']([^"']*)["']/.exec(lines[j]);
    if (descMatch) texts.push({ value: descMatch[1], line: j });
    const nameMatch = /\bname\s*=\s*["']([^"']*)["']/.exec(lines[j]);
    if (nameMatch) name = nameMatch[1];
    if (/^\s*def\s/.test(lines[j])) break;
  }

  // The decorated def: tool name defaults to the function name; docstring is
  // the description FastMCP sends to clients.
  for (let j = i + 1; j < Math.min(lines.length, i + 8); j++) {
    const defMatch = /^\s*(?:async\s+)?def\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(/.exec(lines[j]);
    if (!defMatch) continue;
    name = name ?? defMatch[1];
    for (let k = j + 1; k < Math.min(lines.length, j + 4); k++) {
      const open = /^\s*(?:[rbu]*)("""|''')/.exec(lines[k]);
      if (!open) {
        if (lines[k].trim() !== "" && !/^\s*#/.test(lines[k])) break;
        continue;
      }
      const quote = open[1];
      const docLines: string[] = [];
      let closed = false;
      for (let m = k; m < Math.min(lines.length, k + 40); m++) {
        const content = m === k ? lines[m].slice(lines[m].indexOf(quote) + 3) : lines[m];
        const endIdx = content.indexOf(quote);
        if (endIdx >= 0) {
          docLines.push(content.slice(0, endIdx));
          closed = true;
          break;
        }
        docLines.push(content);
      }
      if (closed || docLines.length > 0) texts.push({ value: docLines.join("\n"), line: k });
      break;
    }
    break;
  }

  if (!name || texts.length === 0) return undefined;
  return { name, texts };
}

/** All tool names defined in the file, for cross-tool shadowing detection. */
function collectPyToolNames(lines: string[]): Set<string> {
  const names = new Set<string>();
  for (let i = 0; i < lines.length; i++) {
    const def = extractPyToolAtLine(lines, i);
    if (def) names.add(def.name);
  }
  return names;
}

/** Variable names assigned directly from an LLM call within the given lines. */
function assignedVarsFromLlmCalls(candidateLines: string[]): Set<string> {
  const names = new Set<string>();
  for (const l of candidateLines) {
    if (!matchesAny(l, LLM_CALL_PATTERNS)) continue;
    const m = /^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=/.exec(l);
    if (m) names.add(m[1]);
  }
  return names;
}

// ── Auth decorator patterns ───────────────────────────────────────────────
const AUTH_DECORATORS = [
  /@login_required/,
  /@require_http_methods/,
  /@permission_required/,
  /@jwt_required/,
  /@token_required/,
  /@requires_auth/,
  /verify_token/,
  /get_current_user/,
  /HTTPBearer/,
  /OAuth2PasswordBearer/,
  /Depends\s*\(\s*get_current/,
];

// ── Injection phrases in strings ──────────────────────────────────────────
const INJECTION_PHRASES = [
  "ignore previous",
  "ignore all previous",
  "disregard previous",
  "forget previous",
  "override instructions",
  "new instructions",
  "act as",
  "you are now",
  "system prompt",
  "developer mode",
  "jailbreak",
  "do anything now",
  "bypass",
];

// ── Sanitization signals ──────────────────────────────────────────────────
const SANITIZATION_SIGNALS = [
  /sanitize|escape|encode|validate|allowlist|whitelist|strip|bleach|markupsafe/i,
];

// ── Helpers ───────────────────────────────────────────────────────────────

function windowText(lines: string[], index: number, before = 0, after = 8): string {
  const start = Math.max(0, index - before);
  const end = Math.min(lines.length - 1, index + after);
  return lines.slice(start, end + 1).join("\n");
}

function matchesAny(text: string, patterns: RegExp[]): boolean {
  return patterns.some((p) => p.test(text));
}

function hasSanitization(text: string): boolean {
  return SANITIZATION_SIGNALS.some((p) => p.test(text));
}

function isTestFile(relPath: string): boolean {
  const normalized = relPath.toLowerCase().replace(/\\/g, "/");
  const base = normalized.split("/").pop() ?? "";
  return (
    normalized.includes("/tests/") ||
    normalized.startsWith("tests/") ||
    normalized.includes("/test/") ||
    normalized.startsWith("test/") ||
    base.endsWith("_test.py") ||
    base.startsWith("test_") ||
    base === "conftest.py"
  );
}

function findingBase(
  ruleId: string,
  title: string,
  severity: Severity,
  filePath: string,
  line: number,
): Omit<Finding, "summary" | "description" | "recommendation" | "confidence" | "evidence"> {
  return { rule_id: ruleId, title, severity, file: filePath, line };
}

// ── Rules ─────────────────────────────────────────────────────────────────

/**
 * Find the start of the function enclosing line `i`, by walking backward to
 * the nearest `def` at a shallower indentation. Falls back to a fixed cap
 * when no enclosing def is found (e.g. module-level code).
 */
function findEnclosingFunctionStart(lines: string[], i: number): number {
  const FALLBACK_CAP = 60;
  const indentOf = (l: string) => (/^(\s*)/.exec(l)?.[1].length ?? 0);
  const callIndent = indentOf(lines[i]);
  for (let j = i - 1; j >= 0 && j >= i - 400; j--) {
    if (/^\s*(async\s+)?def\s+\w+\s*\(/.test(lines[j]) && indentOf(lines[j]) < callIndent) {
      return j;
    }
  }
  return Math.max(0, i - FALLBACK_CAP);
}

/**
 * Collect variable names tainted by request data within [start, upTo],
 * propagating through direct assignment and string composition (fixpoint,
 * a few passes). This lets AI001 see taint that flows through ordinary
 * business logic (logging, rate limiting, RAG lookups) between the request
 * read and the LLM call — a fixed line-distance window missed this whenever
 * a handler had more than a handful of lines in between.
 */
function collectRequestTaintedVars(lines: string[], start: number, upTo: number): Set<string> {
  const tainted = new Set<string>();
  for (let pass = 0; pass < 4; pass++) {
    let changed = false;
    for (let j = start; j <= upTo; j++) {
      const m = /^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.+)$/.exec(lines[j]);
      if (!m) continue;
      const [, name, rhs] = m;
      if (tainted.has(name)) continue;
      const rhsIsTainted =
        matchesAny(rhs, REQUEST_PATTERNS) ||
        [...tainted].some((t) => new RegExp(`\\b${t}\\b`).test(rhs));
      if (rhsIsTainted) {
        tainted.add(name);
        changed = true;
      }
    }
    if (!changed) break;
  }
  return tainted;
}

function checkAI001(lines: string[], i: number, file: string): Finding | null {
  const line = lines[i];
  if (!matchesAny(line, LLM_CALL_PATTERNS)) return null;

  const start = findEnclosingFunctionStart(lines, i);
  const promptWindow = windowText(lines, i, 30, 10);
  if (hasSanitization(promptWindow)) return null;

  const directRequest = matchesAny(promptWindow, REQUEST_PATTERNS);
  const taintedVars = collectRequestTaintedVars(lines, start, i);
  const taintedVarUsed = [...taintedVars].some((v) => new RegExp(`\\b${v}\\b`).test(promptWindow));

  if (!directRequest && !taintedVarUsed) return null;

  // Direct textual match on this call's own window is stronger evidence than
  // a variable that was tainted several assignments earlier and carried
  // forward — the latter has more room for an intervening sanitizer we
  // didn't recognize.
  const evidence = directRequest ? "likely" : "heuristic";

  return {
    ...findingBase("AI001", "Prompt injection via user input", "high", file, i + 1),
    summary: "User request data flows into an LLM call without sanitization.",
    description:
      "Request parameters (request.json, request.form, etc.) are used in an LLM call without role separation or encoding. An attacker can inject instructions that override your system prompt.",
    recommendation:
      'Use separate message roles: messages=[{"role":"system","content":system_prompt},{"role":"user","content":str(user_input)}]',
    confidence: evidenceConfidence(evidence),
    evidence,
  };
}

function checkAI002(lines: string[], i: number, file: string, ctx: FileContext): Finding | null {
  if (!ctx.fileHasLlm) return null;
  const line = lines[i];
  const isLogCall = /\b(logging\s*\.\s*(info|debug|warning|error|critical)|print\s*\(|logger\s*\.\s*(info|debug))/.test(line);
  if (!isLogCall) return null;

  const hasSensitiveField = /\b(prompt|response|completion|token|api_key|password|secret|email)\b/i.test(line);
  if (!hasSensitiveField) return null;

  return {
    ...findingBase("AI002", "Sensitive prompt or response data logged", "high", file, i + 1),
    summary: "Prompt or response content is being logged.",
    description:
      "Logging prompts or responses can expose user data, PII, and model outputs to log storage systems accessible by unintended parties.",
    recommendation:
      "Avoid logging raw prompts or responses. Log only a request ID. If logging is required, redact sensitive fields first.",
    confidence: evidenceConfidence("heuristic"),
    evidence: "heuristic",
  };
}

function checkAI003(lines: string[], i: number, file: string): Finding | null {
  const line = lines[i];
  const isRouteDecorator = /^\s*@\s*(app|router|blueprint)\s*\.\s*(route|get|post|put|delete|patch)\s*\(/.test(line);
  if (!isRouteDecorator) return null;

  // Collect the next 30 lines (the route handler body)
  const handlerText = windowText(lines, i, 0, 30);
  if (!matchesAny(handlerText, LLM_CALL_PATTERNS)) return null;

  // If there's an auth decorator anywhere in the 4 lines before the route
  const beforeRoute = windowText(lines, i, 4, 0);
  if (matchesAny(beforeRoute, AUTH_DECORATORS)) return null;
  if (matchesAny(handlerText, AUTH_DECORATORS)) return null;

  return {
    ...findingBase("AI003", "LLM call before authentication", "critical", file, i + 1),
    summary: "Route handler makes an LLM call with no visible authentication decorator.",
    description:
      "An LLM call is made in a route handler without @login_required, JWT validation, or equivalent auth middleware. Unauthenticated callers can trigger model usage.",
    recommendation:
      "Add @login_required, @jwt_required, or a Depends(get_current_user) guard before the handler. Always authenticate before any LLM invocation.",
    confidence: evidenceConfidence("likely"),
    evidence: "likely",
  };
}

function checkAI004(lines: string[], i: number, file: string): Finding | null {
  const line = lines[i];
  // json.dumps(user) or json.dumps(session) → likely going to LLM
  const hasSensitiveObj = /json\s*\.\s*dumps\s*\(\s*(user|session|profile|account|customer|member)\b/.test(line);
  if (!hasSensitiveObj) return null;

  const ctx = windowText(lines, i, 0, 8);
  if (!matchesAny(ctx, LLM_CALL_PATTERNS)) return null;

  return {
    ...findingBase("AI004", "Sensitive data sent to LLM", "high", file, i + 1),
    summary: "Full user/session object serialized and sent to an LLM.",
    description:
      "Serializing an entire user, session, or profile object exposes PII and internal fields to the LLM provider. Fields like passwords, tokens, or internal IDs should never leave your system.",
    recommendation:
      "Send only the fields needed: minimal = {'name': user.name, 'plan': user.plan}. Never serialize full ORM objects.",
    confidence: evidenceConfidence("heuristic"),
    evidence: "heuristic",
  };
}

function checkAI005(lines: string[], i: number, file: string, ctx: FileContext): Finding | null {
  if (!ctx.fileHasLlm) return null;
  const line = lines[i];
  const matchedSink = EXEC_SINKS.find((s) => s.pattern.test(line));
  if (!matchedSink) return null;

  // Only inspect the sink's *arguments*, not the whole line — otherwise the
  // assignment target of `result = subprocess.run(...)` (an LLM-shaped name
  // that has nothing to do with the sink call) is mistaken for tainted input.
  const sinkMatch = matchedSink.pattern.exec(line);
  const parenIdx = sinkMatch ? line.indexOf("(", sinkMatch.index) : -1;
  const argsFirstLine = parenIdx >= 0 ? line.slice(parenIdx + 1) : "";
  const argsWindow = [argsFirstLine, ...windowText(lines, i, 0, 5).split("\n").slice(1)].join("\n");

  const beforeLines = lines.slice(Math.max(0, i - 10), i);
  const llmVars = assignedVarsFromLlmCalls(beforeLines);
  const confirmedDataflow = [...llmVars].some((v) => new RegExp(`\\b${v}\\b`).test(argsWindow));

  if (confirmedDataflow) {
    return {
      ...findingBase("AI005", "Unsafe LLM output handling", "critical", file, i + 1),
      summary: `LLM output passed to ${matchedSink.label} — a dangerous execution sink.`,
      description:
        "LLM outputs are non-deterministic and can contain attacker-crafted payloads. Passing them to exec(), eval(), subprocess, or SQL queries allows remote code/SQL execution.",
      recommendation:
        "Never pass raw LLM output to execution sinks. Validate against an allowlist, use a schema, and run in a sandbox if code execution is required.",
      confidence: evidenceConfidence("likely"),
      evidence: "likely",
    };
  }

  // Weaker fallback: no confirmed assignment link, but an LLM-result-shaped
  // name appears in the sink's arguments and an LLM call happens nearby.
  // Report at a lower tier since this is name-only proximity, not dataflow.
  const hasGenericVarInArgs = LLM_RESULT_VAR_PATTERNS.some((p) => p.test(argsWindow));
  const nearbyLlmCall = matchesAny(beforeLines.join("\n"), LLM_CALL_PATTERNS);
  if (!hasGenericVarInArgs || !nearbyLlmCall) return null;

  return {
    ...findingBase("AI005", "Possible unsafe LLM output handling", "high", file, i + 1),
    summary: `A variable that may hold LLM output is passed to ${matchedSink.label}.`,
    description:
      "LLM outputs are non-deterministic and can contain attacker-crafted payloads. Passing them to exec(), eval(), subprocess, or SQL queries allows remote code/SQL execution.",
    recommendation:
      "Never pass raw LLM output to execution sinks. Validate against an allowlist, use a schema, and run in a sandbox if code execution is required.",
    confidence: evidenceConfidence("heuristic"),
    evidence: "heuristic",
  };
}

function checkAI006(lines: string[], i: number, file: string): Finding | null {
  const line = lines[i];
  // tools=[ in an LLM call
  if (!/tools\s*=\s*\[/.test(line)) return null;

  const ctx = windowText(lines, i, 2, 15);
  const DANGEROUS_WORDS = ["delete", "remove", "exec", "shell", "command", "email", "send", "purchase", "payment", "deploy", "write", "fetch"];
  const hasDangerous = DANGEROUS_WORDS.some((w) => ctx.toLowerCase().includes(w));
  if (!hasDangerous) return null;

  const APPROVAL_WORDS = ["approve", "confirm", "authorize", "human", "permission", "review"];
  const hasApproval = APPROVAL_WORDS.some((w) => ctx.toLowerCase().includes(w));
  if (hasApproval) return null;

  return {
    ...findingBase("AI006", "Excessive LLM agency", "critical", file, i + 1),
    summary: "LLM configured with high-impact tools without an approval gate.",
    description:
      "The model appears able to invoke tools that delete, execute, email, or deploy without requiring explicit human approval. A prompt injection attack can trigger these actions.",
    recommendation:
      "Require human confirmation before executing high-impact tool calls. Log all tool invocations. Scope tools to the minimum required permissions.",
    confidence: evidenceConfidence("heuristic"),
    evidence: "heuristic",
  };
}

function checkAI007(lines: string[], i: number, file: string): Finding | null {
  const line = lines[i];
  // system=f"...{docs}..." or "role":"system" with retrieved docs variable
  const hasSystemWithDocs =
    /system\s*=\s*f["'].*\{(docs|context|retrieved|chunks|results)/.test(line) ||
    /["']role["']\s*:\s*["']system["'].*\{(docs|context|retrieved|chunks)/.test(line);
  if (!hasSystemWithDocs) return null;

  return {
    ...findingBase("AI007", "RAG context injected into system prompt", "high", file, i + 1),
    summary: "Retrieved documents are concatenated directly into the system prompt.",
    description:
      "Retrieved RAG documents placed in the system prompt are treated as trusted instructions. A poisoned document in the vector store can hijack model behavior.",
    recommendation:
      'Place retrieved context in user-role messages, not system: messages=[{"role":"system","content":base_instructions},{"role":"user","content":f"Context: {docs}\\n{query}"}]',
    confidence: evidenceConfidence("likely"),
    evidence: "likely",
  };
}

function checkAI010(lines: string[], i: number, file: string): Finding | null {
  const line = lines[i];
  const isFetch = /\b(requests|httpx|urllib)\s*\.\s*(get|post|request)\s*\(/.test(line);
  if (!isFetch) return null;

  // Look for .text or .json() or .content used in LLM call ahead
  const ahead = windowText(lines, i, 0, 12);
  const usesContent = /\.(text|content|json\s*\(\))\b/.test(ahead);
  if (!usesContent) return null;
  if (!matchesAny(ahead, LLM_CALL_PATTERNS)) return null;
  if (hasSanitization(ahead)) return null;

  return {
    ...findingBase("AI010", "Indirect prompt injection via HTTP response", "high", file, i + 1),
    summary: "External HTTP response content flows into an LLM call.",
    description:
      "Content fetched from an external URL is passed to an LLM. An attacker who controls the external resource can plant injection instructions that override your system prompt.",
    recommendation:
      'Treat fetched content as untrusted. Place it in a user-role message: messages=[{"role":"system","content":system},{"role":"user","content":f"External content (untrusted):\\n{page_text}"}]',
    confidence: evidenceConfidence("likely"),
    evidence: "likely",
  };
}

function checkVEC001(lines: string[], i: number, file: string): Finding | null {
  const line = lines[i];
  if (!matchesAny(line, VECTOR_SEARCH_PATTERNS)) return null;

  // If there's a filter= keyword arg in this line or the next 3 lines, it's safe
  const ctx = windowText(lines, i, 0, 3);
  const hasFilter = /\bfilter\s*=|where\s*=|namespace\s*=|metadata_filter\s*=/.test(ctx);
  if (hasFilter) return null;

  return {
    ...findingBase("VEC001", "Vector search without access control filter", "high", file, i + 1),
    summary: "Similarity search called with no per-user or per-tenant filter.",
    description:
      "Without a filter, this search returns results from all documents in the vector store. User A's query can retrieve User B's private documents, which the LLM then surfaces in its response.",
    recommendation:
      "Pass a filter scoped to the authenticated user: vectorstore.similarity_search(query, k=5, filter={'user_id': current_user.id})",
    confidence: evidenceConfidence("likely"),
    evidence: "likely",
  };
}

function checkVEC003(lines: string[], i: number, file: string): Finding | null {
  const line = lines[i];
  if (!matchesAny(line, VECTOR_INGEST_PATTERNS)) return null;

  // Check if request data appears in the same line or the 3 lines before
  const ctx = windowText(lines, i, 3, 0);
  const hasRequestSource = matchesAny(ctx + "\n" + line, REQUEST_PATTERNS);
  if (!hasRequestSource) return null;
  if (hasSanitization(ctx + line)) return null;

  return {
    ...findingBase("VEC003", "User-controlled content ingested into vector store", "high", file, i + 1),
    summary: "User-supplied request data is ingested into the vector store without sanitization.",
    description:
      "Allowing users to inject documents into a shared vector store enables RAG data poisoning. A malicious user plants a document with injection instructions that execute when later retrieved by any user.",
    recommendation:
      "Sanitize and validate all user-provided content before ingestion. Store user submissions in an isolated namespace pending review.",
    confidence: evidenceConfidence("likely"),
    evidence: "likely",
  };
}

// Evidence this `description=`/`"description":` field is actually MCP tool
// metadata (arriving from a listing/discovery call), not an unrelated
// config or dataclass field that happens to describe something LLM-shaped
// (e.g. a `system_prompt: str` constructor parameter's docstring).
const MCP_LISTING_HINT = /list_tools|listtools|list_mcp_tools|mcp_tools|tools_result|available_tools/i;

function checkMCP001(lines: string[], i: number, file: string): Finding | null {
  const line = lines[i];
  // Look for description field in a dict-like context
  if (!/"description"\s*:|description\s*=/.test(line)) return null;

  const lower = line.toLowerCase();
  const matched = INJECTION_PHRASES.find((phrase) => lower.includes(phrase));
  if (!matched) return null;

  const ctx = windowText(lines, i, 8, 2);
  if (!MCP_LISTING_HINT.test(ctx)) return null;

  return {
    ...findingBase("MCP001", "MCP tool description contains injection language", "high", file, i + 1),
    summary: `Tool description contains injection phrase: "${matched}".`,
    description:
      "Tool descriptions are sent to the LLM as part of its context. A malicious or compromised MCP server can include override instructions in a description field, hijacking model behavior for the entire session.",
    recommendation:
      "Validate all tool descriptions against an injection-phrase blocklist before registering. Pin third-party MCP servers to known-good versions.",
    confidence: evidenceConfidence("likely"),
    evidence: "likely",
  };
}

function checkMCP007(lines: string[], i: number, file: string, ctx: FileContext): Finding | null {
  if (!ctx.fileHasMcpServer) return null;
  const def = extractPyToolAtLine(lines, i);
  if (!def) return null;

  for (const text of [{ value: def.name, line: i }, ...def.texts]) {
    const invisible = findInvisibleUnicode(text.value);
    if (!invisible) continue;
    return {
      ...findingBase("MCP007", "Invisible Unicode in MCP tool metadata", "critical", file, text.line + 1),
      summary: `Tool "${def.name}" metadata contains ${invisible.codePoint} (${invisible.label}).`,
      description:
        "Invisible or bidirectional Unicode in tool metadata hides content from human reviewers while the model still reads it — the canonical tool-poisoning delivery mechanism.",
      recommendation:
        "Remove the invisible characters and audit how they were introduced; treat the tool definition as compromised until reviewed.",
      confidence: evidenceConfidence("proven"),
      evidence: "proven",
    };
  }
  return null;
}

function checkMCP008(lines: string[], i: number, file: string, ctx: FileContext): Finding | null {
  if (!ctx.fileHasMcpServer) return null;
  const def = extractPyToolAtLine(lines, i);
  if (!def) return null;

  for (const text of def.texts) {
    const phrases = matchInjectionPhrases(text.value);
    if (phrases.strong.length > 0) {
      return {
        ...findingBase("MCP008", "Injection phrasing in MCP tool description", "high", file, text.line + 1),
        summary: `Tool "${def.name}" description contains ${phrases.strong[0]}.`,
        description:
          "The description contains instructions aimed at the agent rather than documentation for the user — the pattern used by real-world tool-poisoning attacks. Descriptions enter the model's context as trusted content.",
        recommendation:
          "Rewrite the description as plain documentation. If this text was not written by your team, treat the package as compromised.",
        confidence: evidenceConfidence("likely"),
        evidence: "likely",
      };
    }
    if (phrases.weak.length >= 2) {
      return {
        ...findingBase("MCP008", "Injection phrasing in MCP tool description", "medium", file, text.line + 1),
        summary: `Tool "${def.name}" description combines ${phrases.weak.length} agent-directive phrases (${phrases.weak.join("; ")}).`,
        description:
          "Multiple agent-directed phrases in one description suggest it is steering the model's behavior rather than documenting the tool.",
        recommendation:
          "Review whether these directives belong in tool metadata; move behavioral policy into your own system prompt.",
        confidence: evidenceConfidence("heuristic"),
        evidence: "heuristic",
      };
    }
  }
  return null;
}

function checkMCP009(lines: string[], i: number, file: string, ctx: FileContext): Finding | null {
  if (!ctx.fileHasMcpServer || !ctx.mcpToolNames || ctx.mcpToolNames.size < 2) return null;
  const def = extractPyToolAtLine(lines, i);
  if (!def) return null;

  for (const text of def.texts) {
    const crossTool = findCrossToolReference(text.value, def.name, ctx.mcpToolNames);
    if (!crossTool) continue;
    return {
      ...findingBase("MCP009", "MCP tool description steers another tool", "medium", file, text.line + 1),
      summary: `Tool "${def.name}" description directs behavior around tool "${crossTool.referencedTool}" ("${crossTool.directive.trim()}…").`,
      description:
        "A tool description that dictates when or how a different tool is used is the tool-shadowing attack: a malicious server manipulates calls that flow to legitimate tools it does not own.",
      recommendation:
        "Tool descriptions should document only their own tool. Cross-tool orchestration belongs in your agent's own policy, not in server-supplied metadata.",
      confidence: evidenceConfidence("likely"),
      evidence: "likely",
    };
  }
  return null;
}

// ── Registered rule functions ─────────────────────────────────────────────

interface FileContext {
  fileHasLlm: boolean;
  fileHasMcpServer: boolean;
  /** Tool names defined in this file (only computed for MCP server files). */
  mcpToolNames?: Set<string>;
}

type RuleChecker = (lines: string[], i: number, file: string, ctx: FileContext) => Finding | null;

const PYTHON_RULES: RuleChecker[] = [
  checkAI001,
  checkAI002,
  checkAI003,
  checkAI004,
  checkAI005,
  checkAI006,
  checkAI007,
  checkAI010,
  checkVEC001,
  checkVEC003,
  checkMCP001,
  checkMCP007,
  checkMCP008,
  checkMCP009,
];

// ── File discovery ────────────────────────────────────────────────────────

const SKIP_DIRS = new Set(["node_modules", ".git", ".venv", "venv", "__pycache__", ".mypy_cache", "dist", "build", ".tox", "site-packages"]);

function findPythonFiles(rootPath: string): string[] {
  const results: string[] = [];

  function walk(dir: string) {
    let entries: fs.Dirent[];
    try {
      entries = fs.readdirSync(dir, { withFileTypes: true });
    } catch {
      return;
    }
    for (const entry of entries) {
      if (SKIP_DIRS.has(entry.name)) continue;
      const full = path.join(dir, entry.name);
      if (entry.isDirectory()) {
        walk(full);
      } else if (entry.isFile() && entry.name.endsWith(".py")) {
        results.push(full);
      }
    }
  }

  walk(rootPath);
  return results;
}

// ── Main scanner ──────────────────────────────────────────────────────────

export interface PythonScanResult {
  findings: Finding[];
  scannedFiles: string[];
}

export function scanPythonFiles(
  rootPath: string,
  options?: { rules?: string[]; blockedRules?: string[]; skipPaths?: string[] },
): PythonScanResult {
  const resolved = path.resolve(rootPath);
  const allPyFiles = findPythonFiles(resolved);

  const skipResolved = (options?.skipPaths ?? []).map((p) =>
    path.resolve(resolved, p).replace(/\\/g, "/"),
  );

  const pyFiles = skipResolved.length === 0
    ? allPyFiles
    : allPyFiles.filter((f) => {
        const normalized = f.replace(/\\/g, "/");
        return !skipResolved.some(
          (skip) => normalized === skip || normalized.startsWith(skip + "/"),
        );
      });
  const findings: Finding[] = [];

  for (const filePath of pyFiles) {
    const testFile = isTestFile(path.relative(resolved, filePath));
    let raw: string;
    try {
      raw = fs.readFileSync(filePath, "utf-8");
    } catch {
      continue;
    }

    const lines = raw.split(/\r?\n/);
    const relPath = path.relative(resolved, filePath);
    const hasMcpServer = fileImportsMcpServerSdk(raw);
    const ctx: FileContext = {
      fileHasLlm: fileImportsLlmSdk(raw),
      fileHasMcpServer: hasMcpServer,
      mcpToolNames: hasMcpServer ? collectPyToolNames(lines) : undefined,
    };

    for (let i = 0; i < lines.length; i++) {
      for (const rule of PYTHON_RULES) {
        // Skip rules not in the requested rule list
        if (options?.rules) {
          // We'll check rule_id after — run first then filter
        }
        const finding = rule(lines, i, relPath, ctx);
        if (!finding) continue;

        // Filter by requested rules and blocked rules
        if (options?.rules && !options.rules.includes(finding.rule_id)) continue;
        if (options?.blockedRules?.includes(finding.rule_id)) continue;

        // Demote evidence for test files
        if (testFile) {
          finding.evidence = demoteEvidence(finding.evidence);
          finding.confidence = evidenceConfidence(finding.evidence);
        }

        findings.push(finding);
      }
    }
  }

  // Deduplicate: same rule + file + line
  const seen = new Set<string>();
  const unique = findings.filter((f) => {
    const key = `${f.rule_id}|${f.file}|${f.line}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });

  return { findings: unique, scannedFiles: pyFiles };
}
