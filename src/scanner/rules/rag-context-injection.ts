import { Node, SyntaxKind } from "ts-morph";
import type { Evidence, Finding, Rule, RuleContext } from "../types.js";
import { getFileCalls, getNodeLine, getRelativeFilePath } from "../../utils/ast.js";
import { demoteEvidence, evidenceConfidence, isTestFilePath } from "../confidence.js";
import { containsIdentifierNamed, getPromptParts, isLikelyLlmCall } from "./llm-rule-utils.js";

// Unambiguous names — only plausible as retrieved RAG content.
const RAG_NAMES_SPECIFIC = new Set([
  "retrieved",
  "retrieveddocs",
  "documents",
  "docs",
  "searchresults",
]);

// "context"/"contexts"/"results"/"chunks" are common names for unrelated
// values (request context, React context, i18n context, arbitrary function
// results, streaming response chunks — `for await (const chunk of stream)`
// is a bread-and-butter LLM SDK pattern with nothing to do with RAG). Only
// count them as RAG content when the enclosing function also shows a
// retrieval call — bare-name matching alone was the same false-positive
// class fixed in the Python scanner's AI005 rule.
const RAG_NAMES_AMBIGUOUS = new Set(["context", "contexts", "results", "chunks"]);

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

// Only the system/developer-role prompt parts count as "privileged" — a bare
// arg or a user-role message is not the injection surface this rule targets.
// Reuses the same role classification AI001 relies on (getPromptParts),
// rather than a separate ad hoc parser that used to fall back to *every*
// call argument, unfiltered by role, whenever the first arg wasn't a plain
// `{ messages: [...] }` object literal.
function systemOrDeveloperMessageContent(call: Node): Node[] {
  return getPromptParts(call)
    .filter((part) => part.role === "system" || part.role === "developer")
    .map((part) => part.node);
}

export const ruleRagContextInjection: Rule = {
  id: "AI007",
  title: "RAG context injected into privileged prompt",
  severity: "high",
  run(context: RuleContext): Finding[] {
    const findings: Finding[] = [];

    for (const sourceFile of context.sourceFiles) {
      const relFile = getRelativeFilePath(context.rootPath, sourceFile);
      const testFile = isTestFilePath(relFile);

      for (const call of getFileCalls(sourceFile)) {
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
          if (testFile) evidence = demoteEvidence(evidence);
          findings.push({
            rule_id: "AI007",
            title: "RAG context injected into privileged prompt",
            severity: "high",
            file: relFile,
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

