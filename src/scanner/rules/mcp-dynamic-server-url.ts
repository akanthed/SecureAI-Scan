import { Node, SyntaxKind } from "ts-morph";
import type { Finding, Rule, RuleContext } from "../types.js";
import { getFileFunctions, getNodeLine, getRelativeFilePath } from "../../utils/ast.js";
import { isTestFilePath, evidenceConfidence } from "../confidence.js";

// Properties in MCP server config that hold the endpoint URL
const MCP_URL_PROPS = [
  "url",
  "baseurl",
  "baseUrl",
  "serverurl",
  "serverUrl",
  "endpoint",
  "host",
  "server",
];

// Variable/property names that indicate MCP server config context
const MCP_CONFIG_CONTEXTS = [
  "mcpserver",
  "mcpconfig",
  "mcp",
  "toolserver",
  "agentserver",
  "remoteserver",
  "toolconfig",
];

// Request-derived taint sources. "req."/"request."/"ctx." are specific
// enough to stand alone (an object actually named that is overwhelmingly an
// HTTP request/context in practice), and already cover genuine chained
// access like "req.body.serverUrl" or "ctx.request.query.url" via substring
// matching. Bare "body."/"query."/"params."/"headers." are deliberately NOT
// included: found via a false positive on `assertOpenLinkParams(params:
// unknown) { ... return { url: params.url } }` in vercel/ai, a URL-scheme
// validator whose parameter happens to be named "params" — an extremely
// common convention for "this function's arguments", unrelated to an actual
// HTTP request. Matching that bare name treated any function taking a
// "params"/"body"/"query"/"headers"-named argument as request-tainted.
const REQUEST_SOURCES = ["req.", "request.", "ctx."];

export function isMcpConfigContext(node: Node): boolean {
  let current: Node | undefined = node.getParent();
  let depth = 0;
  while (current && depth < 6) {
    const text = current.getText().toLowerCase();
    if (MCP_CONFIG_CONTEXTS.some((ctx) => text.includes(ctx))) return true;
    if (Node.isVariableDeclaration(current)) {
      const name = current.getName().toLowerCase();
      if (MCP_CONFIG_CONTEXTS.some((ctx) => name.includes(ctx))) return true;
    }
    current = current.getParent();
    depth++;
  }
  return false;
}

/**
 * Request-derived variables, tracked as *declarations* rather than names. A
 * name is not an identity: found scanning browserbase/mcp-server-browserbase,
 * where `const url = new URL(req.url)` inside an HTTP request handler tainted
 * the unrelated `let url` in the same file's `listen()` callback (the server's
 * own bound address), producing a critical MCP002 on a printed sample config.
 */
export type TaintedDeclarations = Set<Node>;

function variableDeclarationOf(identifier: Node): Node | undefined {
  try {
    return identifier.getSymbol()?.getDeclarations().find((decl) => Node.isVariableDeclaration(decl));
  } catch {
    return undefined;
  }
}

function isTaintedIdentifier(identifier: Node, tainted: TaintedDeclarations): boolean {
  const decl = variableDeclarationOf(identifier);
  return decl !== undefined && tainted.has(decl);
}

export function isUserControlledValue(valueNode: Node, tainted: TaintedDeclarations): boolean {
  const text = valueNode.getText();
  if (REQUEST_SOURCES.some((src) => text.includes(src))) return true;
  if (Node.isIdentifier(valueNode)) return isTaintedIdentifier(valueNode, tainted);
  if (Node.isTemplateExpression(valueNode)) {
    const identifiers = valueNode.getDescendantsOfKind(SyntaxKind.Identifier);
    return identifiers.some((id) => isTaintedIdentifier(id, tainted));
  }
  return false;
}

export function collectRequestDerivedVars(fnNode: Node): TaintedDeclarations {
  const tainted: TaintedDeclarations = new Set<Node>();
  // Deliberately does NOT seed `tainted` from the function's own parameter
  // names. That treated every parameter of every function as "user
  // input" regardless of the function's role — found scanning
  // BerriAI/litellm's ui/litellm-dashboard: extractMCPToken(url: string), a
  // pure URL-parsing utility with no request boundary anywhere nearby, was
  // flagged purely because it has a parameter named "url" that ends up in
  // an object literal under a `baseUrl` key. The known-vulnerable fixture
  // (mcp_dynamic_url.ts) doesn't rely on this: it matches `req.body.serverUrl`
  // directly via REQUEST_SOURCES text below. Only actual evidence — a
  // variable initialized from a request-shaped expression, or propagated
  // from another tainted variable — should seed this set.
  for (const decl of fnNode.getDescendantsOfKind(SyntaxKind.VariableDeclaration)) {
    const init = decl.getInitializer();
    if (!init) continue;
    const initText = init.getText();
    if (REQUEST_SOURCES.some((src) => initText.includes(src))) {
      tainted.add(decl);
    }
    if (Node.isIdentifier(init) && isTaintedIdentifier(init, tainted)) {
      tainted.add(decl);
    }
  }
  return tainted;
}

export const ruleMcpDynamicServerUrl: Rule = {
  id: "MCP002",
  title: "Dynamic MCP server URL from user input",
  severity: "critical",
  run(context: RuleContext): Finding[] {
    const findings: Finding[] = [];

    for (const sourceFile of context.sourceFiles) {
      const relPath = getRelativeFilePath(context.rootPath, sourceFile);
      if (isTestFilePath(relPath)) continue;

      for (const fnNode of getFileFunctions(sourceFile)) {
        const tainted = collectRequestDerivedVars(fnNode);

        for (const objLit of fnNode.getDescendantsOfKind(SyntaxKind.ObjectLiteralExpression)) {
          for (const prop of objLit.getProperties()) {
            if (!Node.isPropertyAssignment(prop)) continue;
            const propName = prop.getNameNode().getText().replace(/['"]/g, "").toLowerCase();
            if (!MCP_URL_PROPS.includes(propName)) continue;

            const valueNode = prop.getInitializer();
            if (!valueNode) continue;
            if (!isUserControlledValue(valueNode, tainted)) continue;
            if (!isMcpConfigContext(prop)) continue;

            findings.push({
              rule_id: "MCP002",
              title: "Dynamic MCP server URL from user input",
              severity: "critical",
              file: relPath,
              line: getNodeLine(prop),
              summary: "MCP server endpoint URL is constructed from user-controlled input.",
              description:
                "Allowing user input to determine which MCP server is connected lets an attacker point your agent at a malicious server they control. That server can return adversarial tool definitions and responses, fully redirecting agent behavior.",
              recommendation:
                "Keep MCP server URLs in server-side configuration only. Never accept them from client requests. Use a hardcoded allowlist of trusted MCP server endpoints.",
              confidence: evidenceConfidence("likely"),
              evidence: "likely",
            });
          }
        }
      }
    }

    return findings;
  },
};
