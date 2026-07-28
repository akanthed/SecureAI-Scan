/**
 * SPIKE — proof of concept only, not wired into the production scanner.
 *
 * Demonstrates tree-sitter-python (via web-tree-sitter, pure WASM, no
 * native compilation) as a viable replacement for the regex/line-based
 * Python scanner. Ports AI001 (prompt injection via user input) far enough
 * to prove the approach against a concrete, real gap in the current
 * regex-based taint tracker in python-scanner.ts: `collectRequestTaintedVars`
 * only recognizes bare-identifier assignment targets
 * (`/^\s*([A-Za-z_]\w*)\s*=\s*(.+)$/`), so `self.user_message = request.json[...]`
 * — an extremely common shape in class-based handlers (Flask MethodView,
 * FastAPI dependency-injected classes, agent/session state objects) — is
 * invisible to it. A real AST has no such gap: an assignment target is
 * either an `identifier` node or an `attribute` node, and both are visible
 * to a structural walk without enumerating LHS shapes by hand.
 *
 * Deliberately NOT feature-complete: no cross-function propagation, no
 * sanitizer detection, no evidence tiering. Scoped to prove the specific
 * claim — "an AST sees what the regex tracker cannot" — not to replace
 * AI001 outright.
 */
import { Parser, Language, type Node as TSNode } from "web-tree-sitter";

export interface PocFinding {
  line: number;
  summary: string;
  taintedTarget: string;
}

const LLM_IMPORT_MODULES = new Set(["openai", "anthropic", "litellm", "google.generativeai", "cohere"]);

const REQUEST_SOURCE_RE =
  /\brequest\.(?:json|form|args|values|data|headers|cookies)\b|\bflask\.request\b/;

let sharedLanguage: Language | undefined;

async function getLanguage(): Promise<Language> {
  if (sharedLanguage) return sharedLanguage;
  await Parser.init();
  // Resolved relative to this file's location, not cwd — mirrors how a real
  // integration would locate the bundled .wasm grammar file. Compiled output
  // lands at spike/python-ast-poc/dist/, three levels below the repo root.
  const wasmPath = new URL(
    "../../../node_modules/tree-sitter-python/tree-sitter-python.wasm",
    import.meta.url,
  ).pathname.replace(/^\/([A-Za-z]:)/, "$1");
  sharedLanguage = await Language.load(wasmPath);
  return sharedLanguage;
}

/** Text of an assignment's LHS target, whatever shape it is (identifier, attribute, subscript). */
function targetText(node: TSNode): string {
  return node.text.trim();
}

/** True if `node` is (or contains, for tuple/list unpacking) an import of a known LLM SDK module. */
function collectLlmImportedNames(root: TSNode): Set<string> {
  const names = new Set<string>();
  function walk(node: TSNode) {
    if (node.type === "import_statement") {
      for (const child of node.children) {
        if (!child) continue;
        if (child.type === "dotted_name" || child.type === "aliased_import") {
          const dotted = child.type === "aliased_import" ? child.child(0)?.text : child.text;
          if (dotted && LLM_IMPORT_MODULES.has(dotted)) {
            const bound = child.type === "aliased_import" ? child.lastChild?.text : dotted.split(".")[0];
            if (bound) names.add(bound);
          }
        }
      }
    }
    if (node.type === "import_from_statement") {
      const moduleNameNode = node.childForFieldName?.("module_name") ?? node.child(1);
      const moduleName = moduleNameNode?.text ?? "";
      if ([...LLM_IMPORT_MODULES].some((m) => moduleName === m || moduleName.startsWith(m + "."))) {
        // from openai import OpenAI  ->  "OpenAI" is a name backed by an LLM module.
        for (const child of node.children) {
          if (child?.type === "dotted_name" && child.text !== moduleName) names.add(child.text);
        }
      }
    }
    for (let i = 0; i < node.childCount; i++) {
      const c = node.child(i);
      if (c) walk(c);
    }
  }
  walk(root);
  return names;
}

/** Leftmost identifier of a (possibly chained) attribute/call expression: client.chat.completions.create -> "client". */
function leftmostName(node: TSNode): string | undefined {
  let current: TSNode | null = node;
  while (current) {
    if (current.type === "identifier") return current.text;
    if (current.type === "attribute" || current.type === "call" || current.type === "subscript") {
      current = current.childForFieldName?.("object") ?? current.child(0);
      continue;
    }
    return undefined;
  }
  return undefined;
}

/** True if a call's leftmost identifier was assigned from (or literally is) an LLM-imported name. */
function isLlmCall(callNode: TSNode, llmNames: Set<string>, llmClientVars: Set<string>): boolean {
  const fn = callNode.childForFieldName?.("function") ?? callNode.child(0);
  if (!fn) return false;
  const root = leftmostName(fn);
  if (!root) return false;
  return llmNames.has(root) || llmClientVars.has(root);
}

/** Variables assigned as `x = SomeImportedLlmClass(...)` — e.g. `client = openai.OpenAI()`. */
function collectLlmClientVars(root: TSNode, llmNames: Set<string>): Set<string> {
  const vars = new Set<string>();
  function walk(node: TSNode) {
    if (node.type === "assignment") {
      const target = node.childForFieldName?.("left") ?? node.child(0);
      const value = node.childForFieldName?.("right") ?? node.child(2);
      if (target?.type === "identifier" && value) {
        const callFn = value.type === "call" ? (value.childForFieldName?.("function") ?? value.child(0)) : undefined;
        const root2 = callFn ? leftmostName(callFn) : undefined;
        if (root2 && llmNames.has(root2)) vars.add(target.text);
      }
    }
    for (let i = 0; i < node.childCount; i++) {
      const c = node.child(i);
      if (c) walk(c);
    }
  }
  walk(root);
  return vars;
}

/**
 * Collect every assignment target tainted by request data within a function
 * body — the part that structurally beats the regex tracker: `target` can be
 * an `identifier` OR an `attribute` node (self.x = ...), both handled the
 * same way because both are real AST nodes with real `.text`, not a hand-
 * written character-class pattern that only anticipated bare identifiers.
 */
function collectTaintedTargets(functionBody: TSNode): Set<string> {
  const tainted = new Set<string>();
  for (let pass = 0; pass < 4; pass++) {
    let changed = false;
    function walk(node: TSNode) {
      if (node.type === "assignment") {
        const target = node.childForFieldName?.("left") ?? node.child(0);
        const value = node.childForFieldName?.("right") ?? node.child(2);
        if (target && value && (target.type === "identifier" || target.type === "attribute")) {
          const key = targetText(target);
          if (!tainted.has(key)) {
            const valueText = value.text;
            const rhsTainted =
              REQUEST_SOURCE_RE.test(valueText) || [...tainted].some((t) => valueText.includes(t));
            if (rhsTainted) {
              tainted.add(key);
              changed = true;
            }
          }
        }
      }
      for (let i = 0; i < node.childCount; i++) {
        const c = node.child(i);
        if (c) walk(c);
      }
    }
    walk(functionBody);
    if (!changed) break;
  }
  return tainted;
}

function enclosingFunctionBody(node: TSNode): TSNode | undefined {
  let current: TSNode | null = node.parent;
  while (current) {
    if (current.type === "function_definition") {
      return current.childForFieldName?.("body") ?? current.lastChild ?? undefined;
    }
    current = current.parent;
  }
  return undefined;
}

export async function scanPythonSourcePoc(source: string): Promise<PocFinding[]> {
  const Python = await getLanguage();
  const parser = new Parser();
  parser.setLanguage(Python);
  const tree = parser.parse(source);
  if (!tree) return [];

  const root = tree.rootNode;
  const llmNames = collectLlmImportedNames(root);
  const llmClientVars = collectLlmClientVars(root, llmNames);
  const findings: PocFinding[] = [];

  function walk(node: TSNode) {
    if (node.type === "call" && isLlmCall(node, llmNames, llmClientVars)) {
      const body = enclosingFunctionBody(node);
      if (body) {
        const tainted = collectTaintedTargets(body);
        const argsText = node.text;
        const directHit = REQUEST_SOURCE_RE.test(argsText);
        const taintedHit = [...tainted].find((t) => argsText.includes(t));
        if (directHit || taintedHit) {
          findings.push({
            line: node.startPosition.row + 1,
            summary: taintedHit
              ? `LLM call uses tainted target "${taintedHit}" (assigned from request-derived data).`
              : "LLM call directly references request data.",
            taintedTarget: taintedHit ?? "(direct)",
          });
        }
      }
    }
    for (let i = 0; i < node.childCount; i++) {
      const c = node.child(i);
      if (c) walk(c);
    }
  }
  walk(root);
  return findings;
}
