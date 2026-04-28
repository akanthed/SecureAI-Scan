import { Node, SyntaxKind } from "ts-morph";
import type { Finding, Rule, RuleContext } from "../types.js";
import { getNodeLine, getRelativeFilePath } from "../../utils/ast.js";
import {
  containsIdentifierNamed,
  getLlmPromptNodes,
  getObjectProperty,
  isLikelyLlmCall,
} from "./llm-rule-utils.js";

const RAG_NAMES = new Set([
  "context",
  "contexts",
  "retrieved",
  "retrieveddocs",
  "documents",
  "docs",
  "chunks",
  "searchresults",
  "results",
]);

function systemOrDeveloperMessageContent(call: Node): Node[] {
  if (!Node.isCallExpression(call)) {
    return [];
  }
  const firstArg = call.getArguments()[0];
  if (!firstArg || !Node.isObjectLiteralExpression(firstArg)) {
    return getLlmPromptNodes(call);
  }
  const messages = getObjectProperty(firstArg, "messages");
  if (!messages || !Node.isArrayLiteralExpression(messages)) {
    return getLlmPromptNodes(call);
  }

  const nodes: Node[] = [];
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
  return nodes;
}

export const ruleRagContextInjection: Rule = {
  id: "AI007",
  title: "RAG context injected into privileged prompt",
  severity: "high",
  run(context: RuleContext): Finding[] {
    const findings: Finding[] = [];

    for (const sourceFile of context.sourceFiles) {
      for (const call of sourceFile.getDescendantsOfKind(SyntaxKind.CallExpression)) {
        if (!isLikelyLlmCall(call)) {
          continue;
        }

        for (const promptNode of systemOrDeveloperMessageContent(call)) {
          if (!containsIdentifierNamed(promptNode, RAG_NAMES)) {
            continue;
          }
          findings.push({
            rule_id: "AI007",
            title: "RAG context injected into privileged prompt",
            severity: "high",
            file: getRelativeFilePath(context.rootPath, sourceFile),
            line: getNodeLine(promptNode),
            summary: "Retrieved content is mixed into a system/developer prompt.",
            description:
              "Untrusted retrieved documents can contain indirect prompt injection. Putting that content in privileged instructions increases impact.",
            recommendation:
              "Keep retrieved content in user/data messages, delimit it clearly, cite sources, and instruct the model that retrieved text is untrusted data.",
            confidence: 0.8,
          });
        }
      }
    }

    return findings;
  },
};

