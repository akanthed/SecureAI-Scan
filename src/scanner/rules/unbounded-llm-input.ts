import { Node, SyntaxKind } from "ts-morph";
import type { Finding, Rule, RuleContext } from "../types.js";
import { getNodeLine, getRelativeFilePath } from "../../utils/ast.js";
import {
  getLlmPromptNodes,
  getObjectProperty,
  isLikelyLlmCall,
  isRequestLikeNode,
} from "./llm-rule-utils.js";

const LIMIT_METHODS = [".slice(", ".substring(", ".substr(", "truncate", "limit"];
const TOKEN_LIMIT_PROPS = ["max_tokens", "maxtokens", "max_completion_tokens", "maxoutputtokens"];

function hasTokenLimit(call: Node): boolean {
  if (!Node.isCallExpression(call)) {
    return false;
  }
  const firstArg = call.getArguments()[0];
  if (!firstArg || !Node.isObjectLiteralExpression(firstArg)) {
    return false;
  }
  const text = firstArg.getText().toLowerCase();
  return TOKEN_LIMIT_PROPS.some((prop) => text.includes(prop));
}

function hasInputLimit(node: Node): boolean {
  const text = node.getText().toLowerCase();
  return LIMIT_METHODS.some((method) => text.includes(method));
}

export const ruleUnboundedLlmInput: Rule = {
  id: "AI009",
  title: "Unbounded user input sent to LLM",
  severity: "medium",
  run(context: RuleContext): Finding[] {
    const findings: Finding[] = [];

    for (const sourceFile of context.sourceFiles) {
      for (const call of sourceFile.getDescendantsOfKind(SyntaxKind.CallExpression)) {
        if (!isLikelyLlmCall(call) || hasTokenLimit(call)) {
          continue;
        }

        const firstArg = call.getArguments()[0];
        if (firstArg && Node.isObjectLiteralExpression(firstArg)) {
          const input = getObjectProperty(firstArg, "input");
          if (input && !hasInputLimit(input) && isRequestLikeNode(input)) {
            findings.push({
              rule_id: "AI009",
              title: "Unbounded user input sent to LLM",
              severity: "medium",
              file: getRelativeFilePath(context.rootPath, sourceFile),
              line: getNodeLine(input),
              summary: "Request input reaches an LLM call without visible input or output bounds.",
              description:
                "Unbounded user input can cause cost spikes, latency problems, context-window exhaustion, or denial-of-service behavior.",
              recommendation:
                "Add request size limits, truncate or validate prompt input, and set model output token limits.",
              confidence: 0.65,
            });
          }
        }

        for (const promptNode of getLlmPromptNodes(call)) {
          if (!isRequestLikeNode(promptNode) || hasInputLimit(promptNode)) {
            continue;
          }
          findings.push({
            rule_id: "AI009",
            title: "Unbounded user input sent to LLM",
            severity: "medium",
            file: getRelativeFilePath(context.rootPath, sourceFile),
            line: getNodeLine(promptNode),
            summary: "Request input reaches an LLM call without visible input or output bounds.",
            description:
              "Unbounded user input can cause cost spikes, latency problems, context-window exhaustion, or denial-of-service behavior.",
            recommendation:
              "Add request size limits, truncate or validate prompt input, and set model output token limits.",
            confidence: 0.65,
          });
        }
      }
    }

    return findings;
  },
};

