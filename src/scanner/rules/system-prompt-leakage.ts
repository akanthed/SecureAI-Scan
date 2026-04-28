import { Node, SyntaxKind } from "ts-morph";
import type { Finding, Rule, RuleContext } from "../types.js";
import { getNodeLine, getRelativeFilePath } from "../../utils/ast.js";
import { getObjectProperty, getStringValue, isLikelyLlmCall } from "./llm-rule-utils.js";

const SECRET_HINTS = [
  "api key",
  "apikey",
  "secret",
  "token",
  "password",
  "bearer",
  "private key",
  "internal url",
  "admin password",
  "connection string",
];

function privilegedPromptNodes(call: Node): Node[] {
  if (!Node.isCallExpression(call)) {
    return [];
  }
  const firstArg = call.getArguments()[0];
  if (!firstArg || !Node.isObjectLiteralExpression(firstArg)) {
    return [];
  }
  const nodes: Node[] = [];
  const system = getObjectProperty(firstArg, "system");
  if (system) {
    nodes.push(system);
  }
  const messages = getObjectProperty(firstArg, "messages");
  if (messages && Node.isArrayLiteralExpression(messages)) {
    for (const element of messages.getElements()) {
      if (!Node.isObjectLiteralExpression(element)) {
        continue;
      }
      const role = getObjectProperty(element, "role")?.getText().replace(/['"`]/g, "").toLowerCase();
      if (role !== "system" && role !== "developer") {
        continue;
      }
      const content = getObjectProperty(element, "content");
      if (content) {
        nodes.push(content);
      }
    }
  }
  return nodes;
}

export const ruleSystemPromptLeakage: Rule = {
  id: "AI008",
  title: "Sensitive data in system prompt",
  severity: "high",
  run(context: RuleContext): Finding[] {
    const findings: Finding[] = [];

    for (const sourceFile of context.sourceFiles) {
      for (const call of sourceFile.getDescendantsOfKind(SyntaxKind.CallExpression)) {
        if (!isLikelyLlmCall(call)) {
          continue;
        }
        for (const promptNode of privilegedPromptNodes(call)) {
          const literalText = getStringValue(promptNode)?.toLowerCase();
          const nodeText = literalText ?? promptNode.getText().toLowerCase();
          if (!SECRET_HINTS.some((hint) => nodeText.includes(hint))) {
            continue;
          }
          findings.push({
            rule_id: "AI008",
            title: "Sensitive data in system prompt",
            severity: "high",
            file: getRelativeFilePath(context.rootPath, sourceFile),
            line: getNodeLine(promptNode),
            summary: "System/developer prompt appears to contain sensitive implementation data.",
            description:
              "System prompts can be exposed through prompt injection, logs, traces, or provider tooling. They should not contain secrets or privileged internals.",
            recommendation:
              "Move secrets and internal credentials to server-side configuration and expose only non-sensitive policy instructions to the model.",
            confidence: 0.75,
          });
        }
      }
    }

    return findings;
  },
};

