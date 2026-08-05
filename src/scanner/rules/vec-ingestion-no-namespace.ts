import { Node, SyntaxKind } from "ts-morph";
import type { Finding, Rule, RuleContext } from "../types.js";
import { getFileCalls, getNodeLine, getRelativeFilePath } from "../../utils/ast.js";
import { evidenceConfidence, demoteEvidence, isTestFilePath } from "../confidence.js";

// Write-side methods that add documents/vectors to a store
const INGESTION_METHODS = [
  "adddocuments",
  "add_documents",
  "addtexts",
  "add_texts",
  "upsert",
  "insert",
  "ingest",
  "indexdocuments",
  "index_documents",
  "fromtexts",
  "from_texts",
  "fromdocuments",
  "from_documents",
];

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
  "supabase",
  "opensearch",
  "elasticsearchvectorstore",
  "mongodbatlasvectorsearch",
  "azureaisearch",
];

// Argument keys that establish tenant/owner partitioning at ingestion time
const NAMESPACE_KEYS = [
  "namespace",
  "tenant",
  "userid",
  "user_id",
  "ownerid",
  "owner_id",
  "partition",
  "acl",
  "tenantid",
  "tenant_id",
];

// "supabase" and "opensearch" are generic clients also used for ordinary
// (non-vector) database writes — e.g. supabase.from("orders").insert(data).
// Require an explicit vector/embedding signal somewhere in the call before
// flagging these two, mirroring the same guard in vec-search-no-access-control.ts.
const AMBIGUOUS_CLIENTS = new Set(["supabase", "opensearch"]);
const VECTOR_CONTEXT_HINT = /vector|embedding|knn|semantic/;

function isVectorIngestionCall(node: Node): boolean {
  if (!Node.isCallExpression(node)) return false;
  const exprText = node.getExpression().getText().toLowerCase();
  const matchedClient = VECTOR_STORE_CLIENTS.find((c) => exprText.includes(c));
  if (!matchedClient) return false;
  if (!INGESTION_METHODS.some((m) => exprText.endsWith(m))) return false;
  if (AMBIGUOUS_CLIENTS.has(matchedClient) && !VECTOR_CONTEXT_HINT.test(node.getText().toLowerCase())) {
    return false;
  }
  return true;
}

function hasNamespaceArg(call: Node): boolean {
  if (!Node.isCallExpression(call)) return false;
  const argsText = call.getArguments().map((a) => a.getText().toLowerCase()).join(" ");
  return NAMESPACE_KEYS.some((k) => argsText.includes(k));
}

export const ruleVecIngestionNoNamespace: Rule = {
  id: "VEC004",
  title: "Vector store ingestion without tenant/namespace tagging",
  severity: "high",
  run(context: RuleContext): Finding[] {
    const findings: Finding[] = [];

    for (const sourceFile of context.sourceFiles) {
      const relPath = getRelativeFilePath(context.rootPath, sourceFile);
      const isTest = isTestFilePath(relPath);

      for (const call of getFileCalls(sourceFile)) {
        if (!isVectorIngestionCall(call)) continue;
        if (hasNamespaceArg(call)) continue;

        findings.push({
          rule_id: "VEC004",
          title: "Vector store ingestion without tenant/namespace tagging",
          severity: "high",
          file: relPath,
          line: getNodeLine(call),
          summary:
            "Documents are ingested into the vector store without a namespace, tenant, or owner identifier in the metadata.",
          description:
            "VEC001 flags similarity searches that lack an access-control filter, but that filter is only meaningful if every document was stamped with the correct owner at ingestion time. A codebase can pass VEC001 and still suffer cross-tenant data leakage when the partition key was never established at write time. This is the write-side dual of VEC001: if addDocuments does not attach a namespace or tenant tag, the read-side filter has nothing to key on.",
          recommendation:
            "Always include a per-tenant or per-user namespace/metadata field when ingesting documents. For example: store.addDocuments(docs, { namespace: userId }) or include { metadata: { tenantId } } in each document. Ensure the same key is used in your VEC001 read filter.",
          confidence: evidenceConfidence(isTest ? demoteEvidence("likely") : "likely"),
          evidence: isTest ? demoteEvidence("likely") : "likely",
        });
      }
    }

    return findings;
  },
};
