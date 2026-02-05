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

const SENSITIVE_OBJECT_NAMES = [
  "user",
  "profile",
  "metadata",
  "session",
  "request",
  "payload",
];

function isLikelyLlmCall(node: Node): boolean {
  if (!Node.isCallExpression(node)) {
    return false;
  }
  const expressionText = node.getExpression().getText().toLowerCase();
  return LLM_CALLEE_PATTERNS.some((pattern) => expressionText.includes(pattern));
}

function isSensitiveObjectIdentifier(node: Node): boolean {
  if (!Node.isIdentifier(node)) {
    return false;
  }
  const name = node.getText().toLowerCase();
  return SENSITIVE_OBJECT_NAMES.some((s) => name === s);
}

function isJsonStringify(node: Node): boolean {
  if (!Node.isCallExpression(node)) {
    return false;
  }
  const expressionText = node.getExpression().getText().toLowerCase();
  return expressionText === "json.stringify" || expressionText.endsWith(".json.stringify");
}

function argContainsSensitiveObject(arg: Node): boolean {
  if (isSensitiveObjectIdentifier(arg)) {
    return true;
  }
  const identifiers = arg.getDescendantsOfKind(SyntaxKind.Identifier);
  return identifiers.some(isSensitiveObjectIdentifier);
}

function getPromptNodes(call: Node): Node[] {
  if (!Node.isCallExpression(call)) {
    return [];
  }
  const args = call.getArguments();
  if (args.length === 0) {
    return [];
  }
  const firstArg = args[0];
  if (!Node.isObjectLiteralExpression(firstArg)) {
    return args;
  }

  const nodes: Node[] = [];
  const props = firstArg.getProperties();
  for (const prop of props) {
    if (!Node.isPropertyAssignment(prop)) {
      continue;
    }
    const name = prop.getNameNode().getText().replace(/['"]/g, "");
    if (name === "prompt") {
      nodes.push(prop.getInitializerOrThrow());
    }
    if (name === "messages") {
      const init = prop.getInitializerOrThrow();
      if (Node.isArrayLiteralExpression(init)) {
        for (const element of init.getElements()) {
          if (!Node.isObjectLiteralExpression(element)) {
            continue;
          }
          const contentProp = element
            .getProperties()
            .find(
              (p) =>
                Node.isPropertyAssignment(p) &&
                p.getNameNode().getText().replace(/['"]/g, "") === "content",
            );
          if (contentProp && Node.isPropertyAssignment(contentProp)) {
            nodes.push(contentProp.getInitializerOrThrow());
          }
        }
      }
    }
  }
  return nodes.length > 0 ? nodes : args;
}

export const ruleSensitiveDataToLlm: Rule = {
  id: "AI004",
  title: "Sensitive data sent to LLM",
  severity: "high",
  run(context: RuleContext): Finding[] {
    const findings: Finding[] = [];

    for (const sourceFile of context.sourceFiles) {
      const calls = sourceFile.getDescendantsOfKind(
        SyntaxKind.CallExpression,
      );

      for (const call of calls) {
        if (!isLikelyLlmCall(call)) {
          continue;
        }

        const promptNodes = getPromptNodes(call);
        for (const arg of promptNodes) {
          const hitsSensitiveObject = argContainsSensitiveObject(arg);
          const hitsJsonStringify =
            isJsonStringify(arg) ||
            arg
              .getDescendantsOfKind(SyntaxKind.CallExpression)
              .some(isJsonStringify);

          if (!hitsSensitiveObject && !hitsJsonStringify) {
            continue;
          }

          findings.push({
            rule_id: "AI004",
            title: "Sensitive data sent to LLM",
            severity: "high",
            file: getRelativeFilePath(context.rootPath, sourceFile),
            line: getNodeLine(arg),
            summary: "Large user context sent directly to LLM.",
            description:
              "Potential PII exposure risk: user/profile/session data is sent to an LLM without minimization.",
            recommendation:
              "Minimize or redact sensitive fields before sending to LLMs; send only necessary attributes.",
            confidence: calculateConfidence({
              directUserInput: true,
              stringConcatOrTemplate: false,
              requestObjectSource: hitsSensitiveObject,
              confirmedLlmCall: true,
            }),
          });
        }
      }
    }

    return findings;
  },
};
