import { Node, SyntaxKind } from "ts-morph";
import type { Evidence, Finding, Rule, RuleContext } from "../types.js";
import { getNodeLine, getRelativeFilePath } from "../../utils/ast.js";
import { demoteEvidence, evidenceConfidence, isTestFilePath } from "../confidence.js";
import { getObjectProperty, getStringValue, isLikelyLlmCall } from "./llm-rule-utils.js";

// Multi-word phrases are specific enough that a bare substring match rarely
// collides with ordinary prose.
const SPECIFIC_SECRET_PHRASES = [
  "api key",
  "apikey",
  "private key",
  "internal url",
  "admin password",
  "connection string",
];

// Single common words ("secret", "token", "password", "bearer") show up
// constantly in ordinary narrative/example prompt text — "a secret door",
// "a token of appreciation" — which is a common LLM demo pattern (fiction
// summarization, creative writing). Only count these when they're attached
// to a value that looks like an actual credential (contains a digit, dash,
// or underscore), not a plain English word.
const LABELED_SECRET_VALUE_RE =
  /\b(secret|token|password|bearer)\b\s*[:=]?\s*['"]?[A-Za-z0-9_\-.]*[0-9_-][A-Za-z0-9_\-.]{5,}/i;

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
      const relFile = getRelativeFilePath(context.rootPath, sourceFile);
      const testFile = isTestFilePath(relFile);

      for (const call of sourceFile.getDescendantsOfKind(SyntaxKind.CallExpression)) {
        if (!isLikelyLlmCall(call)) {
          continue;
        }
        for (const promptNode of privilegedPromptNodes(call)) {
          const literalText = getStringValue(promptNode)?.toLowerCase();
          const nodeText = literalText ?? promptNode.getText().toLowerCase();
          const hasSpecificPhrase = SPECIFIC_SECRET_PHRASES.some((hint) => nodeText.includes(hint));
          if (!hasSpecificPhrase && !LABELED_SECRET_VALUE_RE.test(nodeText)) {
            continue;
          }
          let evidence: Evidence = "likely";
          if (testFile) evidence = demoteEvidence(evidence);
          findings.push({
            rule_id: "AI008",
            title: "Sensitive data in system prompt",
            severity: "high",
            file: relFile,
            line: getNodeLine(promptNode),
            summary: "System/developer prompt appears to contain sensitive implementation data.",
            description:
              "System prompts can be exposed through prompt injection, logs, traces, or provider tooling. They should not contain secrets or privileged internals.",
            recommendation:
              "Move secrets and internal credentials to server-side configuration and expose only non-sensitive policy instructions to the model.",
            confidence: evidenceConfidence(evidence),
            evidence,
          });
        }
      }
    }

    return findings;
  },
};

