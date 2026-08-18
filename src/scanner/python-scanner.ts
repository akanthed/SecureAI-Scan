import fs from "node:fs";
import path from "node:path";
import type { Finding, Severity } from "./types.js";
import { evidenceConfidence, demoteEvidence, isTestFilePath } from "./confidence.js";
import {
  findCrossToolReference,
  findInvisibleUnicode,
  matchInjectionPhrases,
} from "./tool-poisoning-checks.js";
import {
  analyzePythonSource,
  type PythonSource,
} from "./python-source.js";
import {
  pythonCallName,
  pythonDescendants,
  pythonNodeContainsText,
  pythonTargetText,
  type PythonCallNode,
  type PythonNode,
} from "./python-ast.js";

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

// ── Receiver-resolved LLM calls ───────────────────────────────────────────
// The patterns above hardcode receiver names (`client`, `llm`, `chain`,
// `model`), so renaming the variable silently disabled every Python rule.
// These resolve the receiver instead: a variable bound to a known SDK
// constructor in the same file makes any invocation-shaped method call on it
// an LLM sink, whatever it is named. This is the Python analogue of the TS
// scanner's import-resolved `resolveLlmSink`.
const PY_LLM_CONSTRUCTORS = [
  /\b(?:Async)?(?:Azure)?OpenAI\s*\(/,
  /\b(?:Async)?Anthropic(?:Bedrock|Vertex)?\s*\(/,
  /\bgenai\s*\.\s*(?:Client|GenerativeModel)\s*\(/,
  /\bGenerativeModel\s*\(/,
  /\bChat(?:OpenAI|Anthropic|GoogleGenerativeAI|VertexAI|Bedrock|BedrockConverse|MistralAI|Cohere|Ollama|Groq|Fireworks|Together|LiteLLM)\s*\(/,
  /\b(?:LLMChain|ConversationChain|RetrievalQA|ConversationalRetrievalChain)\s*\.?\s*(?:from_\w+\s*)?\(/,
  /\bboto3\s*\.\s*client\s*\(\s*["']bedrock[\w-]*["']/,
  /\bcohere\s*\.\s*(?:Async)?Client(?:V2)?\s*\(/,
  /\b(?:Mistral|MistralClient|MistralAsyncClient)\s*\(/,
  /\b(?:ollama\s*\.\s*Client|Ollama|VertexAI|LlamaCPP|HuggingFacePipeline)\s*\(/,
  /\.\s*as_(?:query_engine|chat_engine|retriever)\s*\(/,
  /\|\s*(?:StrOutputParser\s*\(\s*\)|llm\b)/,
];

const MAX_TRACKED_RECEIVERS = 60;

function escapeRe(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

/**
 * Variables (including `self.x` attributes) assigned from a known LLM SDK
 * constructor anywhere in the file, compiled into call-site matchers.
 */
function collectLlmReceiverNames(src: PythonSource): Set<string> {
  const names = new Set<string>();
  for (const assignment of src.ast.assignments) {
    if (!PY_LLM_CONSTRUCTORS.some((pattern) => pattern.test(assignment.value.text))) continue;
    for (const targetNode of assignment.targets) {
      const target = pythonTargetText(targetNode);
      names.add(target);
      const shortName = target.split(".").pop();
      if (shortName) names.add(shortName);
    }
    if (names.size >= MAX_TRACKED_RECEIVERS) break;
  }
  return names;
}

const PY_LLM_METHOD_NAME = new RegExp(
  String.raw`(?:^|\.)(?:create|parse|stream|completion|acompletion|text_completion|generate_content(?:_async)?|invoke_model|converse|ainvoke|invoke|astream|abatch|batch|predict|run|query|chat|complete|generate)$`,
);

function isLlmCallNode(call: PythonCallNode, receiverNames: Set<string>): boolean {
  const name = pythonCallName(call);
  if (!PY_LLM_METHOD_NAME.test(name)) return false;
  if (matchesAny(`${call.node.text}(`, LLM_CALL_PATTERNS)) return true;
  return [...receiverNames].some(
    (receiver) => name === receiver || name.startsWith(`${receiver}.`) || name.startsWith(`self.${receiver}.`),
  );
}

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
  // Excludes `re.search(...)`/`regex.search(...)` — Python's stdlib regex
  // search, unrelated to vector stores. Found scanning BerriAI/litellm:
  // `re.search(r"/vector_stores/([^/]+)/", path)` (URL-path parsing) matched
  // only because the *regex pattern string* happened to contain the
  // substring "vector", nothing to do with a vector-store client.
  /(?<!\bre)(?<!\bregex)\.\s*search\s*\(\s*[^)]*vector/i,
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

function fileImportsLlmSdk(src: PythonSource): boolean {
  return src.ast.imports.some((node) => PY_LLM_IMPORT_PATTERNS.some((pattern) => pattern.test(node.text)));
}

// ── MCP server SDK import detection (FastMCP / official mcp package) ──────
const PY_MCP_IMPORT_PATTERNS = [
  /^\s*(?:import|from)\s+mcp\b/m,
  /^\s*(?:import|from)\s+fastmcp\b/m,
];

function fileImportsMcpServerSdk(src: PythonSource): boolean {
  return src.ast.imports.some((node) => PY_MCP_IMPORT_PATTERNS.some((pattern) => pattern.test(node.text)));
}

// ── MCP tool decorator extraction ─────────────────────────────────────────

interface PyToolDefinition {
  name: string;
  decoratorLine: number;
  /** description= kwarg text and/or the decorated function's docstring. */
  texts: Array<{ value: string; line: number }>;
}

function pythonStringValue(node: PythonNode): string {
  const text = node.text;
  const quote = text.match(/^(?:[rubfRUBF]*)("""|'''|"|')/)?.[1];
  if (!quote) return text;
  const start = text.indexOf(quote) + quote.length;
  const end = text.endsWith(quote) ? text.length - quote.length : text.length;
  return text.slice(start, end);
}

function collectPyTools(src: PythonSource): PyToolDefinition[] {
  const tools: PyToolDefinition[] = [];
  for (const fn of src.ast.functions) {
    const decorator = fn.decorators.find((candidate) =>
      /@\s*[\w.]*\.?tool(?:\s*\(|\s*$)/.test(candidate.text),
    );
    if (!decorator) continue;

    let name = fn.name;
    const texts: PyToolDefinition["texts"] = [];
    for (const keyword of pythonDescendants(decorator, "keyword_argument")) {
      const keywordName = keyword.childForFieldName("name")?.text;
      const value = keyword.childForFieldName("value");
      if (!value) continue;
      if (keywordName === "name") name = pythonStringValue(value);
      if (keywordName === "description") {
        texts.push({ value: pythonStringValue(value), line: value.startPosition.row });
      }
    }

    const firstStatement = fn.body.namedChildren[0];
    const docstring = firstStatement
      ? pythonDescendants(firstStatement, new Set(["string", "concatenated_string"]))[0]
      : undefined;
    if (docstring) {
      texts.push({ value: pythonStringValue(docstring), line: docstring.startPosition.row });
    }
    if (texts.length > 0) {
      tools.push({ name, decoratorLine: decorator.startPosition.row, texts });
    }
  }
  return tools;
}

function callsWithinNode(src: PythonSource, node: PythonNode): PythonCallNode[] {
  return src.ast.calls.filter(
    (call) => call.node.startIndex >= node.startIndex && call.node.endIndex <= node.endIndex,
  );
}

/** Assignment targets whose value contains an import-resolved LLM call. */
function assignedVarsFromLlmCalls(
  src: PythonSource,
  startLine: number,
  endLine: number,
  ctx: FileContext,
): Set<string> {
  const names = new Set<string>();
  for (const assignment of src.ast.assignmentsBefore(endLine, startLine)) {
    if (!callsWithinNode(src, assignment.value).some(ctx.isLlmCallNode)) continue;
    for (const target of assignment.targets) names.add(pythonTargetText(target));
  }
  return names;
}

/** `\bname\b`, with any attribute dots in `name` treated literally. */
function wordRe(name: string): RegExp {
  return new RegExp(String.raw`\b${escapeRe(name)}\b`);
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
  // FastAPI's idiomatic route auth is a `Depends(...)` dependency — either
  // in the decorator's `dependencies=[...]` kwarg, or (more commonly) as a
  // parameter default (`user: X = Depends(auth_fn)`), which previously
  // wasn't scanned at all: only the decorator and function body were
  // checked, never the parameter list. Found scanning BerriAI/litellm,
  // where every health-check route uses `dependencies=[Depends(user_api_key_auth)]`
  // plus `user_api_key_dict: UserAPIKeyAuth = Depends(user_api_key_auth)` and
  // was still flagged as unauthenticated. Matches by dependency-name/type
  // shape rather than a fixed name list, since real projects name their
  // auth dependency anything.
  /Depends\s*\(\s*\w*(?:auth|token|current_user|api_key|verify|login|session|principal)\w*\s*\)/i,
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
    isTestFilePath(normalized) ||
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
 * Find the AST scope containing a call. Module-level calls use the module as
 * their scope so the same dataflow engine handles scripts and handlers.
 */
function pythonScope(src: PythonSource, node: PythonNode): PythonNode {
  return src.ast.enclosingFunction(node)?.body ?? src.ast.root;
}

/**
 * Collect names tainted by request data within [start, upTo], propagating
 * through assignment and string composition (fixpoint, a few passes). This
 * lets AI001 see taint that flows through ordinary business logic (logging,
 * rate limiting, RAG lookups) between the request read and the LLM call — a
 * fixed line-distance window missed this whenever a handler had more than a
 * handful of lines in between.
 *
 * Operates on reassembled statements, so an assignment split across lines is
 * one unit and a keyword argument on a continuation line is not mistaken for
 * an assignment. Attribute targets are tracked too: `self.user_message =
 * request.json[...]` is the ordinary shape of any class-based handler (Flask
 * `MethodView`, FastAPI dependency classes, agent session state) and was
 * previously invisible.
 */
function collectRequestTaintedVars(src: PythonSource, scope: PythonNode, upTo: number): Set<string> {
  const tainted = new Set<string>();
  const assignments = src.ast.assignments.filter(
    (assignment) =>
      assignment.node.startIndex >= scope.startIndex &&
      assignment.node.endIndex <= scope.endIndex &&
      assignment.node.startPosition.row <= upTo,
  );
  for (let pass = 0; pass < 4; pass++) {
    let changed = false;
    for (const assignment of assignments) {
      const rhsIsTainted =
        matchesAny(assignment.value.text, REQUEST_PATTERNS) ||
        [...tainted].some((target) => pythonNodeContainsText(assignment.value, target));
      if (!rhsIsTainted) continue;
      for (const targetNode of assignment.targets) {
        const target = pythonTargetText(targetNode);
        if (tainted.has(target)) continue;
        tainted.add(target);
        changed = true;
      }
    }
    if (!changed) break;
  }
  return tainted;
}

function checkAI001(src: PythonSource, i: number, file: string, ctx: FileContext): Finding | null {
  if (!ctx.fileHasLlm) return null;
  const call = src.ast.callsAtLine(i).find(ctx.isLlmCallNode);
  if (!call) return null;

  const scope = pythonScope(src, call.node);
  if (hasSanitization(scope.text.slice(0, call.node.endIndex - scope.startIndex))) return null;

  const directRequest = matchesAny(call.node.text, REQUEST_PATTERNS);
  const taintedVars = collectRequestTaintedVars(src, scope, i);
  const taintedVarUsed = [...taintedVars].some((target) =>
    pythonNodeContainsText(call.node, target),
  );
  if (!directRequest && !taintedVarUsed) return null;

  const evidence = "likely";

  return {
    ...findingBase(
      "AI001",
      "Prompt injection via user input",
      "high",
      file,
      call.node.startPosition.row + 1,
    ),
    summary: "User request data flows into an LLM call without sanitization.",
    description:
      "Request parameters (request.json, request.form, etc.) are used in an LLM call without role separation or encoding. An attacker can inject instructions that override your system prompt.",
    recommendation:
      'Use separate message roles: messages=[{"role":"system","content":system_prompt},{"role":"user","content":str(user_input)}]',
    confidence: evidenceConfidence(evidence),
    evidence,
  };
}

function checkAI002(src: PythonSource, i: number, file: string, ctx: FileContext): Finding | null {
  if (!ctx.fileHasLlm) return null;
  const call = src.ast.callsAtLine(i).find((candidate) =>
    /^(?:logging|logger)\.(?:info|debug|warning|error|critical)$|^print$/.test(
      pythonCallName(candidate),
    ),
  );
  if (!call) return null;
  const hasSensitiveField = /\b(prompt|response|completion|token|api_key|password|secret|email)\b/i.test(
    [...call.arguments, ...call.keywords.values()].map((argument) => argument.text).join(" "),
  );
  if (!hasSensitiveField) return null;

  return {
    ...findingBase("AI002", "Sensitive prompt or response data logged", "high", file, call.node.startPosition.row + 1),
    summary: "Prompt or response content is being logged.",
    description:
      "Logging prompts or responses can expose user data, PII, and model outputs to log storage systems accessible by unintended parties.",
    recommendation:
      "Avoid logging raw prompts or responses. Log only a request ID. If logging is required, redact sensitive fields first.",
    confidence: evidenceConfidence("heuristic"),
    evidence: "heuristic",
  };
}

function checkAI003(src: PythonSource, i: number, file: string, ctx: FileContext): Finding | null {
  if (!ctx.fileHasLlm) return null;
  const fn = src.ast.functions.find((candidate) =>
    candidate.decorators.some(
      (decorator) =>
        decorator.startPosition.row === i &&
        /@\s*(?:app|router|blueprint)\s*\.\s*(?:route|get|post|put|delete|patch)\s*\(/.test(
          decorator.text,
        ),
    ),
  );
  if (!fn) return null;
  const handlerCalls = callsWithinNode(src, fn.body);
  if (!handlerCalls.some(ctx.isLlmCallNode)) return null;
  if (fn.decorators.some((decorator) => matchesAny(decorator.text, AUTH_DECORATORS))) return null;
  if (matchesAny(fn.body.text, AUTH_DECORATORS)) return null;
  // The parameter list is where FastAPI auth most commonly lives — a
  // `Depends(...)` default value, invisible to the decorator/body checks
  // above.
  const parameters = fn.node.childForFieldName("parameters");
  if (parameters && matchesAny(parameters.text, AUTH_DECORATORS)) return null;

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

function checkAI004(src: PythonSource, i: number, file: string, ctx: FileContext): Finding | null {
  if (!ctx.fileHasLlm) return null;
  const dumpCall = src.ast.callsAtLine(i).find(
    (call) =>
      pythonCallName(call) === "json.dumps" &&
      call.arguments.some((argument) =>
        /^(?:user|session|profile|account|customer|member)$/.test(argument.text.trim()),
      ),
  );
  if (!dumpCall) return null;
  const scope = pythonScope(src, dumpCall.node);
  const reachesLlm = src.ast.calls.some(
    (call) =>
      call.node.startPosition.row >= i &&
      call.node.startPosition.row <= i + 8 &&
      call.node.startIndex >= scope.startIndex &&
      call.node.endIndex <= scope.endIndex &&
      ctx.isLlmCallNode(call),
  );
  if (!reachesLlm) return null;

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

function checkAI005(src: PythonSource, i: number, file: string, ctx: FileContext): Finding | null {
  if (!ctx.fileHasLlm) return null;
  const call = src.ast.callsAtLine(i).find((candidate) =>
    EXEC_SINKS.some((sink) => sink.pattern.test(`${pythonCallName(candidate)}(`)),
  );
  if (!call) return null;
  const matchedSink = EXEC_SINKS.find((sink) =>
    sink.pattern.test(`${pythonCallName(call)}(`),
  );
  if (!matchedSink) return null;

  const scope = pythonScope(src, call.node);
  const args = [...call.arguments, ...call.keywords.values()];
  const llmVars = assignedVarsFromLlmCalls(
    src,
    scope.startPosition.row,
    i - 1,
    ctx,
  );
  const confirmedDataflow = [...llmVars].some((target) =>
    args.some((argument) => pythonNodeContainsText(argument, target)),
  );

  if (confirmedDataflow) {
    return {
      ...findingBase(
        "AI005",
        "Unsafe LLM output handling",
        "critical",
        file,
        call.node.startPosition.row + 1,
      ),
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
  const argsText = args.map((argument) => argument.text).join("\n");
  const hasGenericVarInArgs = LLM_RESULT_VAR_PATTERNS.some((pattern) => pattern.test(argsText));
  const nearbyLlmCall = src.ast.calls.some(
    (candidate) =>
      candidate.node.startPosition.row >= Math.max(scope.startPosition.row, i - 10) &&
      candidate.node.startPosition.row < i &&
      candidate.node.startIndex >= scope.startIndex &&
      candidate.node.endIndex <= scope.endIndex &&
      ctx.isLlmCallNode(candidate),
  );
  if (!hasGenericVarInArgs || !nearbyLlmCall) return null;

  return {
    ...findingBase(
      "AI005",
      "Possible unsafe LLM output handling",
      "high",
      file,
      call.node.startPosition.row + 1,
    ),
    summary: `A variable that may hold LLM output is passed to ${matchedSink.label}.`,
    description:
      "LLM outputs are non-deterministic and can contain attacker-crafted payloads. Passing them to exec(), eval(), subprocess, or SQL queries allows remote code/SQL execution.",
    recommendation:
      "Never pass raw LLM output to execution sinks. Validate against an allowlist, use a schema, and run in a sandbox if code execution is required.",
    confidence: evidenceConfidence("heuristic"),
    evidence: "heuristic",
  };
}

function checkAI006(src: PythonSource, i: number, file: string, fileCtx: FileContext): Finding | null {
  const call = src.ast.callsAtLine(i).find(
    (candidate) => candidate.keywords.has("tools") && fileCtx.isLlmCallNode(candidate),
  );
  if (!call) return null;
  const scope = pythonScope(src, call.node);
  const ctx = scope.text;
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

function checkAI007(src: PythonSource, i: number, file: string): Finding | null {
  const stringNode = src.ast.strings.find((node) => node.startPosition.row === i);
  if (!stringNode) return null;
  const line = stringNode.text;
  const hasSystemWithDocs =
    /system\s*=\s*f["'][\s\S]*\{(docs|context|retrieved|chunks|results)/.test(line) ||
    /["']role["']\s*:\s*["']system["'][\s\S]*\{(docs|context|retrieved|chunks)/.test(line);
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

function checkAI010(src: PythonSource, i: number, file: string, ctx: FileContext): Finding | null {
  if (!ctx.fileHasLlm) return null;
  const fetchCall = src.ast.callsAtLine(i).find((call) =>
    /^(?:requests|httpx|urllib)(?:\.[\w]+)*\.(?:get|post|request)$/.test(pythonCallName(call)),
  );
  if (!fetchCall) return null;
  const scope = pythonScope(src, fetchCall.node);
  const assignment = src.ast.assignments.find(
    (candidate) =>
      candidate.node.startIndex <= fetchCall.node.startIndex &&
      candidate.node.endIndex >= fetchCall.node.endIndex,
  );
  const targets = assignment?.targets.map(pythonTargetText) ?? [];
  const sink = src.ast.calls.find(
    (call) =>
      call.node.startPosition.row >= i &&
      call.node.startPosition.row <= i + 12 &&
      call.node.startIndex >= scope.startIndex &&
      call.node.endIndex <= scope.endIndex &&
      ctx.isLlmCallNode(call) &&
      (fetchCall.node.startIndex >= call.node.startIndex ||
        targets.some((target) => pythonNodeContainsText(call.node, target))),
  );
  if (!sink || hasSanitization(scope.text.slice(fetchCall.node.startIndex - scope.startIndex, sink.node.endIndex - scope.startIndex))) return null;

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

function checkVEC001(src: PythonSource, i: number, file: string): Finding | null {
  const call = src.ast.callsAtLine(i).find((candidate) =>
    matchesAny(candidate.node.text, VECTOR_SEARCH_PATTERNS),
  );
  if (!call) return null;
  const filterNames = [
    "expr",
    "filter",
    "metadata",
    "metadata_filter",
    "metadata_filters",
    "namespace",
    "query_filter",
    "where",
  ];
  const hasDirectFilter = filterNames.some((name) =>
    call.keywords.has(name),
  );
  if (hasDirectFilter) return null;

  const scope = pythonScope(src, call.node);
  const keywordSplats = call.arguments
    .filter((argument) => argument.type === "dictionary_splat")
    .map((argument) => argument.namedChildren[0]?.text)
    .filter((name): name is string => Boolean(name));
  const hasExpandedFilter = src.ast.assignments.some((assignment) => {
    if (assignment.node.startIndex < scope.startIndex || assignment.node.endIndex >= call.node.startIndex) {
      return false;
    }
    return assignment.targets.some((target) => {
      if (target.type !== "subscript") return false;
      const object = target.childForFieldName("value")?.text;
      const key = target.childForFieldName("subscript")?.text.replace(/^['"]|['"]$/g, "");
      return keywordSplats.includes(object ?? "") && filterNames.includes(key ?? "");
    });
  });
  if (hasExpandedFilter) return null;

  const containingAssignment = src.ast.assignments.find(
    (assignment) =>
      assignment.value.startIndex <= call.node.startIndex &&
      assignment.value.endIndex >= call.node.endIndex,
  );
  const queryTargets = containingAssignment?.targets.map(pythonTargetText) ?? [];
  const hasFluentFilter = src.ast.calls.some((candidate) => {
    if (candidate.node.startIndex < call.node.startIndex) return false;
    if (candidate.node.startIndex < scope.startIndex || candidate.node.endIndex > scope.endIndex) {
      return false;
    }
    const name = pythonCallName(candidate);
    const filterMethod = /\.(?:where|filter|namespace|metadata_filter)$/.test(name);
    if (!filterMethod) return false;
    const containsSearch =
      candidate.node.startIndex <= call.node.startIndex && candidate.node.endIndex >= call.node.endIndex;
    const continuesAssignedQuery = queryTargets.some(
      (target) => name === target || name.startsWith(`${target}.`),
    );
    return containsSearch || continuesAssignedQuery;
  });
  if (hasFluentFilter) return null;

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

function checkVEC003(src: PythonSource, i: number, file: string): Finding | null {
  const call = src.ast.callsAtLine(i).find((candidate) =>
    matchesAny(candidate.node.text, VECTOR_INGEST_PATTERNS),
  );
  if (!call) return null;
  const scope = pythonScope(src, call.node);
  const tainted = collectRequestTaintedVars(src, scope, i);
  const hasRequestSource =
    matchesAny(call.node.text, REQUEST_PATTERNS) ||
    [...tainted].some((target) => pythonNodeContainsText(call.node, target));
  if (!hasRequestSource) return null;
  if (hasSanitization(scope.text.slice(0, call.node.endIndex - scope.startIndex))) return null;

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

function descriptionValueAtLine(src: PythonSource, line: number): PythonNode | undefined {
  return src.ast.strings.find((node) => {
    if (node.startPosition.row !== line) return false;
    let parent: PythonNode | null = node.parent;
    while (parent && parent.startPosition.row >= line - 2) {
      if (parent.type === "keyword_argument") {
        return parent.childForFieldName("name")?.text === "description";
      }
      if (parent.type === "pair") {
        const key = parent.childForFieldName("key");
        return key ? pythonStringValue(key) === "description" : false;
      }
      parent = parent.parent;
    }
    return false;
  });
}

// `pythonScope` falls back to the whole module when a node isn't inside a
// function — fine for taint scoping, but wrong here: a module-level dict
// literal (e.g. an admin-UI settings schema) in a large file inherits "the
// entire file mentions MCP somewhere" as context, which is true of nearly
// any sizeable proxy/server file that also implements real MCP endpoints.
// Found scanning BerriAI/litellm's 17k-line proxy_server.py, where an
// unrelated settings-schema description ("...adds cache_control to the
// system prompt...") matched only because "mcp_tools" appears elsewhere in
// the same file. Cap the module-level fallback to a small line window
// around the description instead of the full file.
const MCP001_MODULE_WINDOW_LINES = 40;

function mcp001Context(src: PythonSource, description: PythonNode, line: number): string {
  const fn = src.ast.enclosingFunction(description);
  if (fn) return fn.body.text;
  const lines = src.ast.root.text.split(/\r?\n/);
  const start = Math.max(0, line - MCP001_MODULE_WINDOW_LINES);
  const end = Math.min(lines.length, line + 5);
  return lines.slice(start, end).join("\n");
}

function checkMCP001(src: PythonSource, i: number, file: string): Finding | null {
  const description = descriptionValueAtLine(src, i);
  if (!description) return null;
  const lower = pythonStringValue(description).toLowerCase();
  const matched = INJECTION_PHRASES.find((phrase) => lower.includes(phrase));
  if (!matched) return null;

  const ctx = mcp001Context(src, description, i);
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

function checkMCP007(src: PythonSource, i: number, file: string, ctx: FileContext): Finding | null {
  if (!ctx.fileHasMcpServer) return null;
  const def = ctx.mcpTools?.find((tool) => tool.decoratorLine === i);
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

function checkMCP008(src: PythonSource, i: number, file: string, ctx: FileContext): Finding | null {
  if (!ctx.fileHasMcpServer) return null;
  const def = ctx.mcpTools?.find((tool) => tool.decoratorLine === i);
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

function checkMCP009(src: PythonSource, i: number, file: string, ctx: FileContext): Finding | null {
  if (!ctx.fileHasMcpServer || !ctx.mcpToolNames || ctx.mcpToolNames.size < 2) return null;
  const def = ctx.mcpTools?.find((tool) => tool.decoratorLine === i);
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
  mcpTools?: PyToolDefinition[];
  /** Tool names defined in this file (only computed for MCP server files). */
  mcpToolNames?: Set<string>;
  /** Import/constructor-resolved AST call predicate. */
  isLlmCallNode: (call: PythonCallNode) => boolean;
}

type RuleChecker = (src: PythonSource, i: number, file: string, ctx: FileContext) => Finding | null;

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

    const src = analyzePythonSource(raw);
    const relPath = path.relative(resolved, filePath);
    const hasMcpServer = fileImportsMcpServerSdk(src);
    const mcpTools = hasMcpServer ? collectPyTools(src) : undefined;
    const receiverNames = collectLlmReceiverNames(src);
    const ctx: FileContext = {
      fileHasLlm: fileImportsLlmSdk(src),
      fileHasMcpServer: hasMcpServer,
      mcpTools,
      mcpToolNames: mcpTools ? new Set(mcpTools.map((tool) => tool.name)) : undefined,
      isLlmCallNode: (call: PythonCallNode) => isLlmCallNode(call, receiverNames),
    };

    for (let i = 0; i < src.lineCount; i++) {
      for (const rule of PYTHON_RULES) {
        // Skip rules not in the requested rule list
        if (options?.rules) {
          // We'll check rule_id after — run first then filter
        }
        const finding = rule(src, i, relPath, ctx);
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
