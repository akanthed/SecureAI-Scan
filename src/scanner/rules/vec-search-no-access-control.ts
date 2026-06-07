import { Node, SyntaxKind } from "ts-morph";
import type { Finding, Rule, RuleContext } from "../types.js";
import { getNodeLine, getRelativeFilePath } from "../../utils/ast.js";
import { calculateConfidence, isTestFilePath } from "../confidence.js";

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

// Parameter/option names that indicate tenant/access filtering
const ACCESS_CONTROL_ARGS = [
  "filter",
  "filters",
  "namespace",
  "tenant",
  "userid",
  "user_id",
  "where",
  "metadata",
  "metadatafilter",
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

function isVectorSearchCall(node: Node): boolean {
  if (!Node.isCallExpression(node)) return false;
  const exprText = node.getExpression().getText().toLowerCase();
  return (
    VECTOR_STORE_CLIENTS.some((client) => exprText.includes(client)) &&
    VECTOR_SEARCH_METHODS.some((method) => exprText.endsWith(method))
  );
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

      for (const call of sourceFile.getDescendantsOfKind(SyntaxKind.CallExpression)) {
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
          confidence: calculateConfidence({
            confirmedLlmCall: false,
            multipleSignals: true,
            isTestFile: isTest,
          }),
        });
      }
    }

    return findings;
  },
};
