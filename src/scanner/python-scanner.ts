import fs from "node:fs";
import path from "node:path";
import type { Finding, Severity } from "./types.js";

// ── Python LLM SDK call patterns ──────────────────────────────────────────
const LLM_CALL_PATTERNS = [
  /openai\s*\.\s*chat\s*\.\s*completions\s*\.\s*create/,
  /client\s*\.\s*chat\s*\.\s*completions\s*\.\s*create/,
  /openai\s*\.\s*ChatCompletion\s*\.\s*create/,
  /anthropic\s*\.\s*messages\s*\.\s*create/,
  /client\s*\.\s*messages\s*\.\s*create/,
  /genai\s*\.\s*generate_content/,
  /model\s*\.\s*generate_content/,
  /bedrock\s*\.\s*invoke_model/,
  /llm\s*\.\s*invoke\s*\(/,
  /llm\s*\.\s*predict\s*\(/,
  /chain\s*\.\s*invoke\s*\(/,
  /chain\s*\.\s*run\s*\(/,
  /ChatOpenAI|ChatAnthropic|ChatGoogleGenerativeAI/,
  /query_engine\s*\.\s*query\s*\(/,
];

// ── User input taint sources ───────────────────────────────────────────────
const REQUEST_PATTERNS = [
  /request\s*\.\s*(json|form|args|data|values|get_json|files)/,
  /body\s*\[\s*['"]/,
  /params\s*\.\s*get\s*\(/,
  /environ\s*\.\s*get\s*\(/,
  /os\.environ\s*\[\s*['"]/,
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

function isTestFile(filePath: string): boolean {
  const normalized = filePath.toLowerCase().replace(/\\/g, "/");
  return (
    normalized.includes("/test") ||
    normalized.includes("_test.py") ||
    normalized.includes("test_.py") ||
    normalized.includes("conftest") ||
    normalized.includes("/tests/")
  );
}

function findingBase(
  ruleId: string,
  title: string,
  severity: Severity,
  filePath: string,
  line: number,
): Omit<Finding, "summary" | "description" | "recommendation" | "confidence"> {
  return { rule_id: ruleId, title, severity, file: filePath, line };
}

// ── Rules ─────────────────────────────────────────────────────────────────

function checkAI001(lines: string[], i: number, file: string): Finding | null {
  const line = lines[i];
  // Look for f-string or string concat with request data
  const hasRequestSource = matchesAny(line, REQUEST_PATTERNS);
  if (!hasRequestSource) return null;

  // Check if an LLM call happens within the next 10 lines
  const ahead = windowText(lines, i, 0, 10);
  if (!matchesAny(ahead, LLM_CALL_PATTERNS)) return null;
  if (hasSanitization(ahead)) return null;

  return {
    ...findingBase("AI001", "Prompt injection via user input", "high", file, i + 1),
    summary: "User request data flows into an LLM call without sanitization.",
    description:
      "Request parameters (request.json, request.form, etc.) are used in an LLM call without role separation or encoding. An attacker can inject instructions that override your system prompt.",
    recommendation:
      'Use separate message roles: messages=[{"role":"system","content":system_prompt},{"role":"user","content":str(user_input)}]',
    confidence: 0.7,
  };
}

function checkAI002(lines: string[], i: number, file: string): Finding | null {
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
    confidence: 0.65,
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
    confidence: 0.6,
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
    confidence: 0.75,
  };
}

function checkAI005(lines: string[], i: number, file: string): Finding | null {
  const line = lines[i];
  const matchedSink = EXEC_SINKS.find((s) => s.pattern.test(line));
  if (!matchedSink) return null;

  // Check if an LLM result variable is referenced in this line
  const hasLlmVar = LLM_RESULT_VAR_PATTERNS.some((p) => p.test(line));
  // Also check the preceding 8 lines for LLM calls whose result flows here
  const before = windowText(lines, i, 8, 0);
  const hasLlmSource = hasLlmVar || matchesAny(before, LLM_CALL_PATTERNS);
  if (!hasLlmSource) return null;

  return {
    ...findingBase("AI005", "Unsafe LLM output handling", "critical", file, i + 1),
    summary: `LLM output passed to ${matchedSink.label} — a dangerous execution sink.`,
    description:
      "LLM outputs are non-deterministic and can contain attacker-crafted payloads. Passing them to exec(), eval(), subprocess, or SQL queries allows remote code/SQL execution.",
    recommendation:
      "Never pass raw LLM output to execution sinks. Validate against an allowlist, use a schema, and run in a sandbox if code execution is required.",
    confidence: 0.8,
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
    confidence: 0.7,
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
    confidence: 0.72,
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
    confidence: 0.65,
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
    confidence: 0.68,
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
    confidence: 0.72,
  };
}

function checkMCP001(lines: string[], i: number, file: string): Finding | null {
  const line = lines[i];
  // Look for description field in a dict-like context
  if (!/"description"\s*:|description\s*=/.test(line)) return null;

  const lower = line.toLowerCase();
  const matched = INJECTION_PHRASES.find((phrase) => lower.includes(phrase));
  if (!matched) return null;

  return {
    ...findingBase("MCP001", "MCP tool description contains injection language", "critical", file, i + 1),
    summary: `Tool description contains injection phrase: "${matched}".`,
    description:
      "Tool descriptions are sent to the LLM as part of its context. A malicious or compromised MCP server can include override instructions in a description field, hijacking model behavior for the entire session.",
    recommendation:
      "Validate all tool descriptions against an injection-phrase blocklist before registering. Pin third-party MCP servers to known-good versions.",
    confidence: 0.93,
  };
}

// ── Registered rule functions ─────────────────────────────────────────────

type RuleChecker = (lines: string[], i: number, file: string) => Finding | null;

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
    const testFile = isTestFile(filePath);
    let raw: string;
    try {
      raw = fs.readFileSync(filePath, "utf-8");
    } catch {
      continue;
    }

    const lines = raw.split(/\r?\n/);
    const relPath = path.relative(resolved, filePath);

    for (let i = 0; i < lines.length; i++) {
      for (const rule of PYTHON_RULES) {
        // Skip rules not in the requested rule list
        if (options?.rules) {
          // We'll check rule_id after — run first then filter
        }
        const finding = rule(lines, i, relPath);
        if (!finding) continue;

        // Filter by requested rules and blocked rules
        if (options?.rules && !options.rules.includes(finding.rule_id)) continue;
        if (options?.blockedRules?.includes(finding.rule_id)) continue;

        // Reduce confidence for test files
        if (testFile) {
          finding.confidence = Math.max(0.1, finding.confidence - 0.3);
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
