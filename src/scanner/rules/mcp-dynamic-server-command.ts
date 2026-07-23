import { Node, SyntaxKind } from "ts-morph";
import type { Finding, Rule, RuleContext } from "../types.js";
import { getNodeLine, getRelativeFilePath } from "../../utils/ast.js";
import { isTestFilePath, evidenceConfidence } from "../confidence.js";
import {
  collectRequestDerivedVars,
  isMcpConfigContext,
  isUserControlledValue,
} from "./mcp-dynamic-server-url.js";

/**
 * MCP010: dynamic MCP client transport command from untrusted input.
 *
 * The MCP stdio transport executes the configured `command` as a real OS
 * command (this is architectural to the protocol, not a bug in any one SDK —
 * see the 2026 CSA/OX Security disclosure on MCP STDIO RCE). If that command
 * — or any of its args — is built from request-derived data instead of a
 * static string, an attacker fully controls what process starts on the host
 * running the MCP client.
 */

// Constructor/property names that identify a stdio transport config, either
// via `new StdioClientTransport({...})` or a bare object literal shaped like
// `StdioServerParameters` (command + args, the same shape either way).
const STDIO_TRANSPORT_NAMES = new Set([
  "stdioclienttransport",
  "stdioservertransport",
  "stdioserverparameters",
]);

function isStdioTransportConstruction(objLit: Node): boolean {
  const parent = objLit.getParent();
  if (parent && Node.isNewExpression(parent)) {
    const name = parent.getExpression().getText().toLowerCase();
    if (STDIO_TRANSPORT_NAMES.has(name)) return true;
  }
  // Fallback: an object literal with both `command` and `args` inside a
  // recognizable MCP config context (mirrors MCP002's guard for the url case).
  return isMcpConfigContext(objLit);
}

function hasCommandAndArgs(objLit: Node): objLit is import("ts-morph").ObjectLiteralExpression {
  if (!Node.isObjectLiteralExpression(objLit)) return false;
  const names = objLit
    .getProperties()
    .filter(Node.isPropertyAssignment)
    .map((p) => p.getNameNode().getText().replace(/['"]/g, "").toLowerCase());
  return names.includes("command") && names.includes("args");
}

export const ruleMcpDynamicServerCommand: Rule = {
  id: "MCP010",
  title: "Dynamic MCP server command from untrusted input",
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
          if (!hasCommandAndArgs(objLit)) continue;
          if (!isStdioTransportConstruction(objLit)) continue;

          for (const prop of objLit.getProperties()) {
            if (!Node.isPropertyAssignment(prop)) continue;
            const propName = prop.getNameNode().getText().replace(/['"]/g, "").toLowerCase();

            if (propName === "command") {
              const valueNode = prop.getInitializer();
              if (valueNode && isUserControlledValue(valueNode, tainted)) {
                findings.push(buildFinding(relPath, prop, "the `command` field", isDirectRequestSource(valueNode)));
              }
            }

            if (propName === "args") {
              const valueNode = prop.getInitializer();
              if (valueNode && Node.isArrayLiteralExpression(valueNode)) {
                for (const element of valueNode.getElements()) {
                  if (!isUserControlledValue(element, tainted)) continue;
                  findings.push(buildFinding(relPath, element, "an `args` element", isDirectRequestSource(element)));
                }
              }
            }
          }
        }
      }
    }

    return findings;
  },
};

// Request-derived taint sources (mirrors the private array in
// mcp-dynamic-server-url.ts — kept local since it's only used to distinguish
// evidence tiers here, not to redo the taint pass).
const DIRECT_REQUEST_SOURCES = ["req.", "request.", "ctx.", "body.", "query.", "params.", "headers."];

function isDirectRequestSource(node: Node): boolean {
  return DIRECT_REQUEST_SOURCES.some((src) => node.getText().includes(src));
}

function buildFinding(relPath: string, node: Node, location: string, direct: boolean): Finding {
  const evidence = direct ? "proven" : "likely";
  return {
    rule_id: "MCP010",
    title: "Dynamic MCP server command from untrusted input",
    severity: "critical",
    file: relPath,
    line: getNodeLine(node),
    summary: `MCP stdio transport ${location} is constructed from user-controlled input.`,
    description:
      "The MCP stdio transport executes the configured command as a real OS process. Letting request-derived data reach the command or its arguments lets an attacker run arbitrary commands with the permissions of the process hosting the MCP client — the same class of risk as passing user input to child_process.exec.",
    recommendation:
      "Keep MCP server commands and arguments in static, server-side configuration. Never build them from request data; use a hardcoded allowlist of trusted commands if the launched server must vary.",
    confidence: evidenceConfidence(evidence),
    evidence,
  };
}
