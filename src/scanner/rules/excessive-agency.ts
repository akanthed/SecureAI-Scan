import { Node, SyntaxKind } from "ts-morph";
import type { Finding, Rule, RuleContext } from "../types.js";
import { getNodeLine, getRelativeFilePath } from "../../utils/ast.js";
import { getObjectProperty, isLikelyLlmCall } from "./llm-rule-utils.js";

const DANGEROUS_TOOL_WORDS = [
  "write",
  "delete",
  "remove",
  "exec",
  "shell",
  "command",
  "email",
  "send",
  "purchase",
  "payment",
  "refund",
  "http",
  "request",
  "fetch",
  "deploy",
];

const APPROVAL_WORDS = ["approve", "approval", "confirm", "authorize", "permission", "human"];

function hasToolConfig(call: Node): Node | undefined {
  if (!Node.isCallExpression(call)) {
    return undefined;
  }
  const firstArg = call.getArguments()[0];
  if (!firstArg || !Node.isObjectLiteralExpression(firstArg)) {
    return undefined;
  }
  return getObjectProperty(firstArg, "tools") ?? getObjectProperty(firstArg, "functions");
}

export const ruleExcessiveAgency: Rule = {
  id: "AI006",
  title: "Excessive LLM agency",
  severity: "critical",
  run(context: RuleContext): Finding[] {
    const findings: Finding[] = [];

    for (const sourceFile of context.sourceFiles) {
      for (const call of sourceFile.getDescendantsOfKind(SyntaxKind.CallExpression)) {
        if (!isLikelyLlmCall(call)) {
          continue;
        }
        const toolConfig = hasToolConfig(call);
        if (!toolConfig) {
          continue;
        }

        const toolText = toolConfig.getText().toLowerCase();
        const hasDangerousTool = DANGEROUS_TOOL_WORDS.some((word) => toolText.includes(word));
        if (!hasDangerousTool) {
          continue;
        }

        const enclosingFunction = call.getFirstAncestor((ancestor) =>
          Node.isFunctionDeclaration(ancestor) ||
          Node.isFunctionExpression(ancestor) ||
          Node.isArrowFunction(ancestor) ||
          Node.isMethodDeclaration(ancestor),
        );
        const functionText = enclosingFunction?.getText().toLowerCase() ?? "";
        const hasApprovalGate = APPROVAL_WORDS.some((word) => functionText.includes(word));
        if (hasApprovalGate) {
          continue;
        }

        findings.push({
          rule_id: "AI006",
          title: "Excessive LLM agency",
          severity: "critical",
          file: getRelativeFilePath(context.rootPath, sourceFile),
          line: getNodeLine(toolConfig),
          summary: "LLM is configured with high-impact tools without an obvious approval gate.",
          description:
            "The model appears able to invoke tools that can change state, communicate externally, execute commands, or call arbitrary services.",
          recommendation:
            "Require explicit authorization, scope tool permissions, validate arguments, and keep high-impact actions behind human or policy gates.",
          confidence: 0.75,
        });
      }
    }

    return findings;
  },
};

