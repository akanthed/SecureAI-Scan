import { Node, SyntaxKind } from "ts-morph";
import type { Finding, Rule, RuleContext } from "../types.js";
import { getNodeLine, getRelativeFilePath } from "../../utils/ast.js";
import { calculateConfidence } from "../confidence.js";

const LLM_CALLEE_PATTERNS = [
  "openai",
  "anthropic",
  "google",
  "gemini",
  "genai",
];

const AUTH_FUNCTIONS = ["auth", "isauthenticated", "requireauth"];

function isLikelyLlmCall(node: Node): boolean {
  if (!Node.isCallExpression(node)) {
    return false;
  }
  const expressionText = node.getExpression().getText().toLowerCase();
  return LLM_CALLEE_PATTERNS.some((pattern) => expressionText.includes(pattern));
}

function isAuthCall(node: Node): boolean {
  if (!Node.isCallExpression(node)) {
    return false;
  }
  const expressionText = node.getExpression().getText().toLowerCase();
  return AUTH_FUNCTIONS.some((name) => expressionText.includes(name));
}

function isRequestHandler(node: Node): boolean {
  if (
    !Node.isFunctionDeclaration(node) &&
    !Node.isFunctionExpression(node) &&
    !Node.isArrowFunction(node) &&
    !Node.isMethodDeclaration(node)
  ) {
    return false;
  }

  return node.getParameters().some((param) => {
    const name = param.getNameNode().getText().toLowerCase();
    return name === "req" || name === "request" || name === "ctx";
  });
}

export const ruleLlmBeforeAuth: Rule = {
  id: "AI003",
  title: "LLM call before authentication",
  severity: "critical",
  run(context: RuleContext): Finding[] {
    const findings: Finding[] = [];

    for (const sourceFile of context.sourceFiles) {
      const functionNodes = sourceFile.getDescendants().filter(isRequestHandler);

      for (const fn of functionNodes) {
        const calls = fn.getDescendantsOfKind(SyntaxKind.CallExpression);
        let authSeen = false;

        for (const call of calls) {
          if (isAuthCall(call)) {
            authSeen = true;
            continue;
          }

          if (!isLikelyLlmCall(call)) {
            continue;
          }

          if (!authSeen) {
            findings.push({
              rule_id: "AI003",
              title: "LLM call before authentication",
              severity: "critical",
              file: getRelativeFilePath(context.rootPath, sourceFile),
              line: getNodeLine(call),
              summary: "LLM call occurs before auth checks.",
              description:
                "LLM call occurs in a request handler before authentication checks.",
              recommendation:
                "Ensure authentication/authorization runs before invoking LLMs in request handlers.",
              confidence: calculateConfidence({
                directUserInput: false,
                stringConcatOrTemplate: false,
                requestObjectSource: true,
                confirmedLlmCall: true,
              }),
            });
          }
        }
      }
    }

    return findings;
  },
};
