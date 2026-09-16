import { Node, SyntaxKind, type SourceFile } from "ts-morph";

/**
 * Import-resolved LLM sink detection.
 *
 * Instead of substring-matching call text ("google" used to make every
 * googleMapsClient.geocode() an "LLM call"), we resolve the leftmost
 * identifier of the call chain back to its declaration and check whether it
 * originates from a known LLM SDK module. Only when resolution fails do we
 * fall back to a (much narrower) name heuristic, and callers can tell the
 * difference via `resolved`.
 */

interface ModuleMatcher {
  provider: string;
  test: (specifier: string) => boolean;
}

const LLM_MODULES: ModuleMatcher[] = [
  { provider: "OpenAI", test: (s) => s === "openai" || s.startsWith("openai/") },
  { provider: "Azure OpenAI", test: (s) => s === "@azure/openai" },
  { provider: "Anthropic", test: (s) => s.startsWith("@anthropic-ai/") },
  { provider: "Google Gemini", test: (s) => s === "@google/generative-ai" || s === "@google/genai" },
  { provider: "Vercel AI SDK", test: (s) => s === "ai" || s.startsWith("@ai-sdk/") },
  { provider: "LangChain", test: (s) => s === "langchain" || s.startsWith("langchain/") || s.startsWith("@langchain/") },
  { provider: "LlamaIndex", test: (s) => s === "llamaindex" || s.startsWith("@llamaindex/") },
  { provider: "Cohere", test: (s) => s === "cohere-ai" },
  { provider: "Mistral", test: (s) => s === "@mistralai/mistralai" },
  { provider: "Groq", test: (s) => s === "groq-sdk" },
  { provider: "Ollama", test: (s) => s === "ollama" },
  { provider: "AWS Bedrock", test: (s) => s === "@aws-sdk/client-bedrock-runtime" },
  { provider: "Together AI", test: (s) => s === "together-ai" },
  { provider: "xAI", test: (s) => s === "@ai-sdk/xai" },
];

/**
 * Narrow fallback for code where resolution fails (untyped JS, indirect
 * construction). Deliberately does NOT include "google" — that matched Maps,
 * Analytics, Sheets clients and was the largest false-positive source.
 */
const FALLBACK_NAME_HINTS = [
  "openai",
  "anthropic",
  "claude",
  "gemini",
  "genai",
  "bedrock",
  "mistral",
  "cohere",
  "chatmodel",
  "llm",
];

/** Method names that indicate a generation/inference call on an LLM client. */
const GENERATION_METHODS = new Set([
  "create",
  "generatecontent",
  "generatecontentstream",
  "generatetext",
  "streamtext",
  "generateobject",
  "streamobject",
  "invoke",
  "call",
  "complete",
  "completions",
  "chat",
  "generate",
  "sendmessage",
  "predict",
  "stream",
  "run",
  "query",
]);

export interface LlmSink {
  /** Human label for the SDK, e.g. "OpenAI". */
  provider: string;
  /** True when established via import resolution, false when name heuristic. */
  resolved: boolean;
  /** Full call expression text, e.g. "openai.chat.completions.create". */
  callText: string;
}

function moduleProvider(specifier: string): string | undefined {
  for (const m of LLM_MODULES) {
    if (m.test(specifier)) return m.provider;
  }
  return undefined;
}

function leftmostIdentifier(node: Node): Node | undefined {
  let current: Node = node;
  for (;;) {
    if (Node.isPropertyAccessExpression(current) || Node.isElementAccessExpression(current)) {
      current = current.getExpression();
      continue;
    }
    if (Node.isCallExpression(current) || Node.isNewExpression(current)) {
      current = current.getExpression();
      continue;
    }
    if (Node.isAwaitExpression(current) || Node.isParenthesizedExpression(current) || Node.isAsExpression(current) || Node.isNonNullExpression(current)) {
      current = current.getExpression();
      continue;
    }
    break;
  }
  return Node.isIdentifier(current) ? current : undefined;
}

/** Resolve an identifier to the module specifier it (transitively) came from. */
function resolveIdentifierModule(identifier: Node, depth = 0): string | undefined {
  if (depth > 5 || !Node.isIdentifier(identifier)) return undefined;

  const symbol = identifier.getSymbol();
  if (!symbol) return undefined;

  for (const decl of symbol.getDeclarations()) {
    // import X from "mod" / import { X } from "mod" / import * as X from "mod"
    if (Node.isImportSpecifier(decl) || Node.isImportClause(decl) || Node.isNamespaceImport(decl)) {
      const importDecl = decl.getFirstAncestorByKind(SyntaxKind.ImportDeclaration);
      const spec = importDecl?.getModuleSpecifierValue();
      if (spec) return spec;
    }

    // const client = new OpenAI(...) / const x = require("openai") / const y = client
    if (Node.isVariableDeclaration(decl)) {
      let init = decl.getInitializer();
      if (!init) continue;
      if (Node.isAwaitExpression(init)) init = init.getExpression();

      // require("mod")
      if (Node.isCallExpression(init) && init.getExpression().getText() === "require") {
        const arg = init.getArguments()[0];
        if (arg && Node.isStringLiteral(arg)) return arg.getLiteralText();
      }

      const inner = leftmostIdentifier(init);
      if (inner && inner !== identifier) {
        const spec = resolveIdentifierModule(inner, depth + 1);
        if (spec) return spec;
      }
    }

    // function param typed as an SDK class: (client: OpenAI) — resolve the type name
    if (Node.isParameterDeclaration(decl)) {
      const typeNode = decl.getTypeNode();
      if (typeNode && Node.isTypeReference(typeNode)) {
        const typeName = typeNode.getTypeName();
        if (Node.isIdentifier(typeName)) {
          const spec = resolveIdentifierModule(typeName, depth + 1);
          if (spec) return spec;
        }
      }
    }
  }
  return undefined;
}

function lastMethodName(callText: string): string {
  const cleaned = callText.split("(")[0];
  const parts = cleaned.split(".");
  return (parts[parts.length - 1] ?? "").replace(/[^A-Za-z]/g, "").toLowerCase();
}

/**
 * Resolve whether a call expression is an LLM generation call.
 * Returns undefined for non-LLM calls.
 *
 * ts-morph's symbol resolver can throw on malformed/edge-case input (e.g.
 * files pulled in from a bundled venv or vendored node_modules that trip up
 * its type checker). A single unparseable file must never abort the whole
 * scan, so resolution errors here are swallowed and treated as "not an LLM
 * call" rather than propagated.
 */
export function resolveLlmSink(node: Node): LlmSink | undefined {
  const cached = sinkCache.get(node);
  if (cached !== undefined) return cached ?? undefined;
  let result: LlmSink | undefined;
  try {
    result = resolveLlmSinkInner(node);
  } catch {
    result = undefined;
  }
  sinkCache.set(node, result ?? null);
  return result;
}

/**
 * Resolution is deterministic for a fixed project, and roughly ten rules ask
 * about the same call expressions. Without this each of them pays for symbol
 * resolution separately.
 */
const sinkCache = new WeakMap<Node, LlmSink | null>();

function resolveLlmSinkInner(node: Node): LlmSink | undefined {
  if (!Node.isCallExpression(node)) return undefined;
  const callText = node.getExpression().getText();
  const method = lastMethodName(callText);

  // Every path below requires a generation-shaped method name, so checking it
  // first is behaviour-preserving — and it keeps the type checker away from
  // call expressions that cannot be a model invocation whatever they resolve to.
  if (!GENERATION_METHODS.has(method)) return undefined;

  const lower = callText.toLowerCase();
  const hinted = FALLBACK_NAME_HINTS.some((h) => lower.includes(h));

  // `resolveIdentifierModule` only ever reports a specifier that this file
  // itself imports or requires: it reads the declarations an identifier binds
  // to in this file (import specifier, local variable, parameter type) and
  // never follows an alias into another module. So when the file imports no
  // LLM SDK, resolution cannot yield a provider, and the only remaining way
  // to return a sink is the name fallback. If that can't fire either, the
  // answer is `undefined` without asking the type checker anything — which is
  // the difference between minutes and seconds on a large repo, where the
  // overwhelming majority of files have nothing to do with an LLM.
  if (!hinted && !fileHasLlmModuleImport(node.getSourceFile())) return undefined;

  const root = leftmostIdentifier(node.getExpression());
  if (root) {
    const spec = resolveIdentifierModule(root);
    if (spec) {
      const provider = moduleProvider(spec);
      if (provider) {
        // Import resolution proves the call reaches an LLM SDK module, but
        // that module is not exclusively model-invocation functions — the
        // Vercel AI SDK, for instance, exports type guards (isToolUIPart),
        // formatters, and schema helpers from the same "ai" package right
        // alongside generateText/streamText. Resolution alone previously
        // treated every one of those as an LLM call (found via a false
        // positive on isToolUIPart() in vercel/ai's own TUI harness — see
        // CHANGELOG). The generation-shaped-verb check that gates this is
        // now hoisted to the top of this function.
        return { provider, resolved: true, callText };
      }
      // Resolved to a known non-LLM module: definitively not an LLM call.
      return undefined;
    }
  }

  // Resolution failed — narrow name fallback.
  if (hinted) {
    return { provider: "unresolved LLM client", resolved: false, callText };
  }
  return undefined;
}

const llmImportCache = new WeakMap<SourceFile, boolean>();

function fileHasLlmModuleImport(sourceFile: SourceFile): boolean {
  const cached = llmImportCache.get(sourceFile);
  if (cached !== undefined) return cached;
  const value = fileImportsLlmSdk(sourceFile);
  llmImportCache.set(sourceFile, value);
  return value;
}

/** Back-compat boolean wrapper used by older rules. */
export function isLikelyLlmCall(node: Node): boolean {
  return resolveLlmSink(node) !== undefined;
}

/** True if the file imports any known LLM SDK (or requires one). */
export function fileImportsLlmSdk(sourceFile: SourceFile): boolean {
  for (const imp of sourceFile.getImportDeclarations()) {
    if (moduleProvider(imp.getModuleSpecifierValue())) return true;
  }
  const text = sourceFile.getFullText();
  const requireMatches = text.matchAll(/require\(\s*["']([^"']+)["']\s*\)/g);
  for (const m of requireMatches) {
    if (moduleProvider(m[1])) return true;
  }
  return false;
}

export function getObjectProperty(
  objectNode: Node,
  propertyName: string,
): Node | undefined {
  if (!Node.isObjectLiteralExpression(objectNode)) {
    return undefined;
  }
  for (const prop of objectNode.getProperties()) {
    if (
      Node.isPropertyAssignment(prop) &&
      prop.getNameNode().getText().replace(/['"]/g, "") === propertyName
    ) {
      return prop.getInitializer();
    }
    // { messages } shorthand
    if (
      Node.isShorthandPropertyAssignment(prop) &&
      prop.getName() === propertyName
    ) {
      return prop.getNameNode();
    }
  }
  return undefined;
}

export interface PromptPart {
  /** "system" | "developer" | "user" | "assistant" | "prompt" | "arg" */
  role: string;
  node: Node;
}

/**
 * Extract prompt content nodes from an LLM call, with the role they play.
 * Understands: messages:[{role, content}], system:, prompt:, input:, and
 * bare string arguments.
 */
export function getPromptParts(call: Node): PromptPart[] {
  if (!Node.isCallExpression(call)) return [];
  const args = call.getArguments();
  if (args.length === 0) return [];

  const firstArg = args[0];
  if (!Node.isObjectLiteralExpression(firstArg)) {
    return args
      .filter((a) => !Node.isObjectLiteralExpression(a))
      .map((a) => ({ role: "arg", node: a }));
  }

  const parts: PromptPart[] = [];

  const messages = getObjectProperty(firstArg, "messages");
  if (messages && Node.isArrayLiteralExpression(messages)) {
    for (const element of messages.getElements()) {
      if (!Node.isObjectLiteralExpression(element)) continue;
      const roleNode = getObjectProperty(element, "role");
      const role = roleNode?.getText().replace(/['"`]/g, "").toLowerCase() ?? "unknown";
      const content = getObjectProperty(element, "content");
      if (content) parts.push({ role, node: content });
    }
  }

  for (const key of ["system", "systemPrompt", "system_prompt", "systemInstruction"]) {
    const prop = getObjectProperty(firstArg, key);
    if (prop) parts.push({ role: "system", node: prop });
  }

  for (const key of ["prompt", "input", "contents"]) {
    const prop = getObjectProperty(firstArg, key);
    if (prop) parts.push({ role: "prompt", node: prop });
  }

  return parts;
}

/** Back-compat: prompt content nodes without role information. */
export function getLlmPromptNodes(call: Node): Node[] {
  return getPromptParts(call).map((p) => p.node);
}

export function getStringValue(node: Node): string | undefined {
  if (Node.isStringLiteral(node) || Node.isNoSubstitutionTemplateLiteral(node)) {
    return node.getLiteralText();
  }
  return undefined;
}

export function containsIdentifierNamed(node: Node, names: Set<string>): boolean {
  if (Node.isIdentifier(node) && names.has(node.getText().toLowerCase())) {
    return true;
  }
  return node
    .getDescendantsOfKind(SyntaxKind.Identifier)
    .some((identifier) => names.has(identifier.getText().toLowerCase()));
}

export function isRequestLikeNode(node: Node): boolean {
  const text = node.getText().toLowerCase();
  return /\b(req|request|ctx)\s*\./.test(text) || /\b(body|query|params)\b/.test(text);
}

/**
 * Resolves a bare-identifier call (`buildPrompt(x)`) to the FunctionDeclaration
 * it invokes, but only when the resolution is completely unambiguous and the
 * declaration lives in a file this scan actually parsed. Used to follow
 * tainted data across a function-call boundary in interprocedural taint
 * tracing (AI001) — deliberately has no name-heuristic fallback path (unlike
 * resolveLlmSink): a call this can't cleanly resolve is a call the caller
 * must not follow, since trusting an unseen function's behavior sight-unseen
 * is the riskiest step in that analysis. Covers both a same-file helper
 * (symbol resolves straight to the FunctionDeclaration) and an imported one
 * (symbol resolves to an ImportSpecifier/Clause/NamespaceImport, one more
 * hop via getAliasedSymbol() reaches the real declaration). Anything else —
 * a reassigned function reference, a method call, an overload set, an
 * external/node_modules declaration — resolves to something other than a
 * single FunctionDeclaration inside `projectFiles` and is rejected.
 */
export function resolveLocalCallTarget(
  call: Node,
  projectFiles: Set<SourceFile>,
): Node | undefined {
  if (!Node.isCallExpression(call)) return undefined;
  const callee = call.getExpression();
  if (!Node.isIdentifier(callee)) return undefined;

  const symbol = callee.getSymbol();
  if (!symbol) return undefined;

  let targetDecls = symbol.getDeclarations();
  if (
    targetDecls.length === 1 &&
    (Node.isImportSpecifier(targetDecls[0]) ||
      Node.isImportClause(targetDecls[0]) ||
      Node.isNamespaceImport(targetDecls[0]))
  ) {
    const aliased = symbol.getAliasedSymbol?.();
    if (!aliased) return undefined;
    targetDecls = aliased.getDeclarations();
  }

  if (targetDecls.length !== 1) return undefined;
  const decl = targetDecls[0];
  if (!Node.isFunctionDeclaration(decl)) return undefined;
  if (!projectFiles.has(decl.getSourceFile())) return undefined;

  return decl;
}
