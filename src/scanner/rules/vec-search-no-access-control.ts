import { Node, SyntaxKind } from "ts-morph";
import type { Finding, Rule, RuleContext } from "../types.js";
import { getFileCalls, getNodeLine, getRelativeFilePath } from "../../utils/ast.js";
import { evidenceConfidence, demoteEvidence, isTestFilePath } from "../confidence.js";

// Method names used for vector similarity search across major SDKs
const VECTOR_SEARCH_METHODS = [
  "similaritysearch",
  "similarity_search",
  "queryvectors",
  "query_vectors",
  "semanticsearch",
  "semantic_search",
  "vectorsearch",
  "vector_search",
  "search",
  "query",
  "retrieve",
  "neartext",
  "near_text",
  "nearobject",
];

// Parameter/option names that indicate tenant/access filtering.
// Deliberately excludes bare "metadata" — an object merely containing a
// metadata key (e.g. { metadata: { source: "pdf" } }) doesn't establish
// tenant/user scoping, so treating it as sufficient access control was a
// false-negative-inducing heuristic.
const ACCESS_CONTROL_ARGS = [
  "filter",
  "filters",
  "namespace",
  "tenant",
  "userid",
  "user_id",
  "where",
  "accessfilter",
  "acl",
];

// Class/object names that signal a vector store client
const VECTOR_STORE_CLIENTS = [
  "chroma",
  "pinecone",
  "weaviate",
  "qdrant",
  "milvus",
  "faiss",
  "vectorstore",
  "vectordb",
  "embeddings",
  "pgvector",
  "supabase",
  "opensearch",
  "elasticsearchvectorstore",
  "mongodbatlasvectorsearch",
  "azureaisearch",
];

// "supabase" and "opensearch" are generic clients also used for ordinary
// (non-vector) database/full-text queries — e.g. supabase.from(...).select()
// or a plain opensearchClient.search() text query. Require an explicit
// vector/embedding signal somewhere in the call before flagging these two.
const AMBIGUOUS_CLIENTS = new Set(["supabase", "opensearch"]);
const VECTOR_CONTEXT_HINT = /vector|embedding|knn|semantic/;

function isVectorSearchCall(node: Node): boolean {
  if (!Node.isCallExpression(node)) return false;
  const exprText = node.getExpression().getText().toLowerCase();
  const matchedClient = VECTOR_STORE_CLIENTS.find((client) => exprText.includes(client));
  if (!matchedClient) return false;
  if (!VECTOR_SEARCH_METHODS.some((method) => exprText.endsWith(method))) return false;
  if (AMBIGUOUS_CLIENTS.has(matchedClient) && !VECTOR_CONTEXT_HINT.test(node.getText().toLowerCase())) {
    return false;
  }
  return true;
}

function hasAccessControlArg(call: Node): boolean {
  if (!Node.isCallExpression(call)) return false;
  const argsText = call.getArguments().map((a) => a.getText().toLowerCase()).join(" ");
  return ACCESS_CONTROL_ARGS.some((arg) => argsText.includes(arg));
}

export const ruleVecSearchNoAccessControl: Rule = {
  id: "VEC001",
  title: "Vector search without tenant/user access control filter",
  severity: "high",
  run(context: RuleContext): Finding[] {
    const findings: Finding[] = [];

    for (const sourceFile of context.sourceFiles) {
      const relPath = getRelativeFilePath(context.rootPath, sourceFile);
      const isTest = isTestFilePath(relPath);

      for (const call of getFileCalls(sourceFile)) {
        if (!isVectorSearchCall(call)) continue;
        if (hasAccessControlArg(call)) continue;

        findings.push({
          rule_id: "VEC001",
          title: "Vector search without tenant/user access control filter",
          severity: "high",
          file: relPath,
          line: getNodeLine(call),
          summary: "Vector similarity search is called without a namespace, filter, or tenant identifier.",
          description:
            "Without a per-user or per-tenant filter, a similarity search returns results from all documents stored in the vector database. User A can receive documents that belong to User B through the LLM's context, causing data leakage across tenant boundaries.",
          recommendation:
            "Always pass a namespace, filter, or where-clause scoped to the authenticated user or tenant. For example: store.similaritySearch(query, k, { filter: { userId: req.user.id } }).",
          confidence: evidenceConfidence(isTest ? demoteEvidence("likely") : "likely"),
          evidence: isTest ? demoteEvidence("likely") : "likely",
        });
      }
    }

    return findings;
  },
};
