import { Node, SyntaxKind } from "ts-morph";
import type { Finding, Rule, RuleContext, TraceStep } from "../types.js";
import { getNodeLine, getRelativeFilePath } from "../../utils/ast.js";
import { isLikelyLlmCall } from "./llm-rule-utils.js";
import { evidenceConfidence, demoteEvidence, isTestFilePath, hasSanitizationNearby } from "../confidence.js";
import type { Evidence } from "../types.js";

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

interface ToolResultOrigin {
  line: number;
  note: string;
}

function collectToolResultVars(fnNode: Node): Map<string, ToolResultOrigin> {
  const vars = new Map<string, ToolResultOrigin>();
  for (const decl of fnNode.getDescendantsOfKind(SyntaxKind.VariableDeclaration)) {
    const name = decl.getName();
    const init = decl.getInitializer();
    const initText = init?.getText().toLowerCase() ?? "";
    if (isToolResultVar(name) || TOOL_RESULT_PATTERNS.some((p) => initText.includes(p))) {
      vars.set(name, { line: getNodeLine(decl), note: `MCP tool result \`${name}\`` });
    }
  }

  // Check function params
  if ("getParameters" in fnNode) {
    for (const param of (fnNode as any).getParameters()) {
      const nameNode = param.getNameNode?.();
      if (nameNode && Node.isIdentifier(nameNode) && isToolResultVar(nameNode.getText())) {
        vars.set(nameNode.getText(), {
          line: getNodeLine(param),
          note: `MCP tool result parameter \`${nameNode.getText()}\``,
        });
      }
    }
  }
  return vars;
}

interface ElevationMatch {
  varName: string;
  role: string;
  contentLine: number;
}

function findElevatedToolResultUsage(
  call: Node,
  toolVars: Map<string, ToolResultOrigin>,
): ElevationMatch | undefined {
  if (!Node.isCallExpression(call)) return undefined;
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
      const contentInit = contentProp.getInitializer();
      const contentText = contentInit?.getText() ?? "";
      for (const varName of toolVars.keys()) {
        if (contentText.includes(varName)) {
          return {
            varName,
            role: roleVal,
            contentLine: contentInit ? getNodeLine(contentInit) : getNodeLine(el),
          };
        }
      }
    }
  }
  return undefined;
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
          const match = findElevatedToolResultUsage(call, toolVars);
          if (!match) continue;

          const evidence: Evidence = hasSanitization ? demoteEvidence("likely") : "likely";
          const origin = toolVars.get(match.varName)!;
          const sinkLine = getNodeLine(call);

          const trace: TraceStep[] = [
            { kind: "source", file: relPath, line: origin.line, note: origin.note },
          ];
          if (match.contentLine !== origin.line) {
            trace.push({
              kind: "flow",
              file: relPath,
              line: match.contentLine,
              note: `placed in ${match.role}-role message content`,
            });
          }
          trace.push({
            kind: "sink",
            file: relPath,
            line: sinkLine,
            note: `${call.getExpression().getText()} — ${match.role} role`,
          });

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
            confidence: evidenceConfidence(evidence),
            evidence,
            trace,
          });
        }
      }
    }

    return findings;
  },
};
