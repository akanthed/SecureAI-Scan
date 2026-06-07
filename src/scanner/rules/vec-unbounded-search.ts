import { Node, SyntaxKind } from "ts-morph";
import type { Finding, Rule, RuleContext } from "../types.js";
import { getNodeLine, getRelativeFilePath } from "../../utils/ast.js";
import { calculateConfidence, isTestFilePath } from "../confidence.js";

// Search method names that accept a k/limit parameter
const VECTOR_SEARCH_METHODS = [
  "similaritysearch",
  "similarity_search",
  "maxmarginalsearchrelevance",
  "mmrsearch",
  "queryvectors",
  "query_vectors",
];

// Vector store client patterns
const VECTOR_STORE_CLIENTS = [
  "chroma",
  "pinecone",
  "weaviate",
  "qdrant",
  "milvus",
  "faiss",
  "vectorstore",
  "vectordb",
  "pgvector",
];

// Request/user-controlled taint sources
const TAINT_SOURCES = ["req.", "request.", "ctx.", "body.", "query.", "params.", "process.env"];

const MAX_SAFE_K = 50;

function isVectorSearchCall(node: Node): boolean {
  if (!Node.isCallExpression(node)) return false;
  const exprText = node.getExpression().getText().toLowerCase();
  return (
    VECTOR_STORE_CLIENTS.some((c) => exprText.includes(c)) &&
    VECTOR_SEARCH_METHODS.some((m) => exprText.endsWith(m))
  );
}

function getKArgument(call: Node): Node | undefined {
  if (!Node.isCallExpression(call)) return undefined;
  const args = call.getArguments();
  // k is typically the second argument
  return args[1];
}

function isUserControlledK(kNode: Node): boolean {
  const text = kNode.getText();
  return TAINT_SOURCES.some((src) => text.includes(src));
}

function isLargeNumericK(kNode: Node): boolean {
  if (Node.isNumericLiteral(kNode)) {
    const val = Number(kNode.getLiteralText());
    return val > MAX_SAFE_K;
  }
  return false;
}

export const ruleVecUnboundedSearch: Rule = {
  id: "VEC002",
  title: "Unbounded or user-controlled vector similarity search limit",
  severity: "medium",
  run(context: RuleContext): Finding[] {
    const findings: Finding[] = [];

    for (const sourceFile of context.sourceFiles) {
      const relPath = getRelativeFilePath(context.rootPath, sourceFile);
      const isTest = isTestFilePath(relPath);

      for (const call of sourceFile.getDescendantsOfKind(SyntaxKind.CallExpression)) {
        if (!isVectorSearchCall(call)) continue;

        const kArg = getKArgument(call);

        // No k argument — returns default (often all results or SDK default)
        if (!kArg) {
          findings.push({
            rule_id: "VEC002",
            title: "Unbounded or user-controlled vector similarity search limit",
            severity: "medium",
            file: relPath,
            line: getNodeLine(call),
            summary: "Vector search called with no k limit — may return all stored documents.",
            description:
              "Without an explicit result count limit, a vector search may return an unbounded number of documents. This can inject excessive retrieved content into LLM context (prompt stuffing), exhaust token budgets, and inadvertently expose documents from unrelated records.",
            recommendation:
              "Always specify an explicit, hardcoded k value appropriate for your use case (typically 3-10). Never derive k from user input.",
            confidence: calculateConfidence({
              multipleSignals: false,
              isTestFile: isTest,
            }),
          });
          continue;
        }

        // k is user-controlled
        if (isUserControlledK(kArg)) {
          findings.push({
            rule_id: "VEC002",
            title: "Unbounded or user-controlled vector similarity search limit",
            severity: "high",
            file: relPath,
            line: getNodeLine(kArg),
            summary: "Vector search k limit is controlled by user input.",
            description:
              "An attacker can set k to a large number, forcing the system to retrieve and process thousands of documents per request. This enables prompt-stuffing attacks, cost exhaustion (LLM token abuse), and potential cross-tenant data exposure.",
            recommendation:
              "Hardcode k as a server-side constant. If k must vary, clamp it to a safe maximum (e.g. Math.min(userK, 10)).",
            confidence: calculateConfidence({
              directUserInput: true,
              requestObjectSource: true,
              multipleSignals: true,
              isTestFile: isTest,
            }),
          });
          continue;
        }

        // k is a suspiciously large number
        if (isLargeNumericK(kArg)) {
          findings.push({
            rule_id: "VEC002",
            title: "Unbounded or user-controlled vector similarity search limit",
            severity: "low",
            file: relPath,
            line: getNodeLine(kArg),
            summary: `Vector search k=${kArg.getText()} is unusually large and may cause token budget issues.`,
            description:
              "A very large k value retrieves a large number of documents per search, which may exceed LLM context limits or unexpectedly expose a broad cross-section of stored data.",
            recommendation:
              `Consider reducing k to 3–10 for typical RAG use cases. The current value of ${kArg.getText()} retrieves far more context than most LLMs can use effectively.`,
            confidence: calculateConfidence({
              multipleSignals: false,
              isTestFile: isTest,
            }),
          });
        }
      }
    }

    return findings;
  },
};
