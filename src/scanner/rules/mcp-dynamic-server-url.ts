import { Node, SyntaxKind } from "ts-morph";
import type { Finding, Rule, RuleContext } from "../types.js";
import { getNodeLine, getRelativeFilePath } from "../../utils/ast.js";
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

// Request-derived taint sources
const REQUEST_SOURCES = ["req.", "request.", "ctx.", "body.", "query.", "params.", "headers."];

function isMcpConfigContext(node: Node): boolean {
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

function isUserControlledValue(valueNode: Node, taintedVars: Set<string>): boolean {
  const text = valueNode.getText();
  if (REQUEST_SOURCES.some((src) => text.includes(src))) return true;
  if (Node.isIdentifier(valueNode) && taintedVars.has(valueNode.getText())) return true;
  if (Node.isTemplateExpression(valueNode)) {
    const identifiers = valueNode.getDescendantsOfKind(SyntaxKind.Identifier);
    return identifiers.some((id) => taintedVars.has(id.getText()));
  }
  return false;
}

function collectRequestDerivedVars(fnNode: Node): Set<string> {
  const tainted = new Set<string>();
  for (const param of "getParameters" in fnNode ? (fnNode as any).getParameters() : []) {
    const nameNode = param.getNameNode?.();
    if (nameNode && Node.isIdentifier(nameNode)) tainted.add(nameNode.getText());
  }
  for (const decl of fnNode.getDescendantsOfKind(SyntaxKind.VariableDeclaration)) {
    const init = decl.getInitializer();
    if (!init) continue;
    const initText = init.getText();
    if (REQUEST_SOURCES.some((src) => initText.includes(src))) {
      tainted.add(decl.getName());
    }
    if (Node.isIdentifier(init) && tainted.has(init.getText())) {
      tainted.add(decl.getName());
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

      for (const fnNode of sourceFile.getDescendants()) {
        if (
          !Node.isFunctionDeclaration(fnNode) &&
          !Node.isFunctionExpression(fnNode) &&
          !Node.isArrowFunction(fnNode) &&
          !Node.isMethodDeclaration(fnNode)
        ) continue;

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
