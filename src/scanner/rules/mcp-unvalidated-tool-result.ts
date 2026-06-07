import { Node, SyntaxKind } from "ts-morph";
import type { Finding, Rule, RuleContext } from "../types.js";
import { getNodeLine, getRelativeFilePath } from "../../utils/ast.js";
import { isLikelyLlmCall } from "./llm-rule-utils.js";
import { calculateConfidence, isTestFilePath, hasSanitizationNearby } from "../confidence.js";

// Variable names suggesting MCP tool call results
const TOOL_RESULT_PATTERNS = [
  "toolresult",
  "tooloutput",
  "toolresponse",
  "toolcallresult",
  "functionresult",
  "functionoutput",
  "mcpresult",
  "mcpresponse",
  "toolcall",
];

// Role values where tool results should not be elevated
const ELEVATED_ROLES = ["system", "developer"];

function isToolResultVar(name: string): boolean {
  return TOOL_RESULT_PATTERNS.some((p) => name.toLowerCase().includes(p));
}

function collectToolResultVars(fnNode: Node): Set<string> {
  const vars = new Set<string>();
  for (const decl of fnNode.getDescendantsOfKind(SyntaxKind.VariableDeclaration)) {
    const name = decl.getName();
    if (isToolResultVar(name)) vars.add(name);
    const init = decl.getInitializer();
    if (init) {
      const initText = init.getText().toLowerCase();
      if (TOOL_RESULT_PATTERNS.some((p) => initText.includes(p))) vars.add(name);
    }
  }

  // Check function params
  if ("getParameters" in fnNode) {
    for (const param of (fnNode as any).getParameters()) {
      const nameNode = param.getNameNode?.();
      if (nameNode && Node.isIdentifier(nameNode) && isToolResultVar(nameNode.getText())) {
        vars.add(nameNode.getText());
      }
    }
  }
  return vars;
}

function toolResultElevatedToHighTrustRole(call: Node, toolVars: Set<string>): boolean {
  if (!Node.isCallExpression(call)) return false;
  for (const arg of call.getArguments()) {
    if (!Node.isObjectLiteralExpression(arg)) continue;
    const messagesNode = arg
      .getProperties()
      .find(
        (p) =>
          Node.isPropertyAssignment(p) &&
          p.getNameNode().getText().replace(/['"]/g, "") === "messages",
      );
    if (!messagesNode || !Node.isPropertyAssignment(messagesNode)) continue;
    const messagesVal = messagesNode.getInitializer();
    if (!messagesVal || !Node.isArrayLiteralExpression(messagesVal)) continue;

    for (const el of messagesVal.getElements()) {
      if (!Node.isObjectLiteralExpression(el)) continue;
      const roleProp = el.getProperties().find(
        (p) => Node.isPropertyAssignment(p) && p.getNameNode().getText().replace(/['"]/g, "") === "role",
      );
      const contentProp = el.getProperties().find(
        (p) => Node.isPropertyAssignment(p) && p.getNameNode().getText().replace(/['"]/g, "") === "content",
      );
      if (!roleProp || !contentProp || !Node.isPropertyAssignment(roleProp) || !Node.isPropertyAssignment(contentProp)) continue;

      const roleVal = roleProp.getInitializer()?.getText().replace(/['"]/g, "").toLowerCase();
      if (!roleVal || !ELEVATED_ROLES.includes(roleVal)) continue;
      const contentText = contentProp.getInitializer()?.getText() ?? "";
      if ([...toolVars].some((v) => contentText.includes(v))) return true;
    }
  }
  return false;
}

export const ruleMcpUnvalidatedToolResult: Rule = {
  id: "MCP003",
  title: "Unvalidated MCP tool result used as trusted LLM context",
  severity: "high",
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

        const toolVars = collectToolResultVars(fnNode);
        if (toolVars.size === 0) continue;

        const hasSanitization = hasSanitizationNearby(fnNode.getText());

        for (const call of fnNode.getDescendantsOfKind(SyntaxKind.CallExpression)) {
          if (!isLikelyLlmCall(call)) continue;
          if (!toolResultElevatedToHighTrustRole(call, toolVars)) continue;

          findings.push({
            rule_id: "MCP003",
            title: "Unvalidated MCP tool result used as trusted LLM context",
            severity: "high",
            file: relPath,
            line: getNodeLine(call),
            summary: "MCP tool call result is placed in a system/developer role without validation.",
            description:
              "Tool results from MCP servers should be treated as untrusted data. Placing them directly into a system-role message means a compromised tool server can inject arbitrary instructions with full system-level trust.",
            recommendation:
              "Always place tool results in the 'tool' role (not 'system' or 'developer'). Validate and sanitize tool outputs before including them in any message context. Use output schemas to restrict the shape of tool responses.",
            confidence: calculateConfidence({
              confirmedLlmCall: true,
              multipleSignals: true,
              hasInputSanitization: hasSanitization,
            }),
          });
        }
      }
    }

    return findings;
  },
};
