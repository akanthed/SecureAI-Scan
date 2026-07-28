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
  try {
    return resolveLlmSinkInner(node);
  } catch {
    return undefined;
  }
}

function resolveLlmSinkInner(node: Node): LlmSink | undefined {
  if (!Node.isCallExpression(node)) return undefined;
  const callText = node.getExpression().getText();
  const method = lastMethodName(callText);

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
        // CHANGELOG). GENERATION_METHODS is the same generation-shaped-verb
        // check already applied on the unresolved fallback path below;
        // requiring it here too closes that gap without weakening the
        // resolved case, since every real SDK entry point (generateText,
        // streamText, chat.completions.create, embeddings.create, …) is
        // already in that set.
        if (GENERATION_METHODS.has(method)) {
          return { provider, resolved: true, callText };
        }
        return undefined;
      }
      // Resolved to a known non-LLM module: definitively not an LLM call.
      return undefined;
    }
  }

  // Resolution failed — narrow name fallback, and require a generation method.
  const lower = callText.toLowerCase();
  const hinted = FALLBACK_NAME_HINTS.some((h) => lower.includes(h));
  if (hinted && GENERATION_METHODS.has(method)) {
    return { provider: "unresolved LLM client", resolved: false, callText };
  }
  return undefined;
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
