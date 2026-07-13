import { Node, SyntaxKind } from "ts-morph";
import type { Evidence, Finding, Rule, RuleContext } from "../types.js";
import { getNodeLine, getRelativeFilePath } from "../../utils/ast.js";
import { evidenceConfidence } from "../confidence.js";
import {
  containsIdentifierNamed,
  getLlmPromptNodes,
  getObjectProperty,
  isLikelyLlmCall,
} from "./llm-rule-utils.js";

// Unambiguous names — only plausible as retrieved RAG content.
const RAG_NAMES_SPECIFIC = new Set([
  "retrieved",
  "retrieveddocs",
  "documents",
  "docs",
  "chunks",
  "searchresults",
]);

// "context"/"contexts"/"results" are common names for unrelated values
// (request context, React context, i18n context, arbitrary function
// results). Only count them as RAG content when the enclosing function
// also shows a retrieval call — bare-name matching alone was the same
// false-positive class fixed in the Python scanner's AI005 rule.
const RAG_NAMES_AMBIGUOUS = new Set(["context", "contexts", "results"]);

const RETRIEVAL_HINT =
  /similaritysearch|similarity_search|vectorstore|vector_store|retriever|\.query\(|pinecone|chroma|weaviate|qdrant|milvus|pgvector|embeddings?\.search/i;

function enclosingScopeText(node: Node): string {
  const fn = node.getFirstAncestor(
    (a) =>
      Node.isFunctionDeclaration(a) ||
      Node.isFunctionExpression(a) ||
      Node.isArrowFunction(a) ||
      Node.isMethodDeclaration(a),
  );
  return (fn ?? node.getSourceFile()).getText();
}

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
          let evidence: Evidence | undefined;
          if (containsIdentifierNamed(promptNode, RAG_NAMES_SPECIFIC)) {
            evidence = "likely";
          } else if (
            containsIdentifierNamed(promptNode, RAG_NAMES_AMBIGUOUS) &&
            RETRIEVAL_HINT.test(enclosingScopeText(promptNode))
          ) {
            evidence = "heuristic";
          }
          if (!evidence) {
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
            confidence: evidenceConfidence(evidence),
            evidence,
          });
        }
      }
    }

    return findings;
  },
};

