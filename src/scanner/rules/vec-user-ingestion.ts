import { Node, SyntaxKind } from "ts-morph";
import type { Finding, Rule, RuleContext } from "../types.js";
import { getNodeLine, getRelativeFilePath } from "../../utils/ast.js";
import { evidenceConfidence, demoteEvidence, isTestFilePath, hasSanitizationNearby } from "../confidence.js";

// Methods used to ingest content into vector stores
const INGESTION_METHODS = [
  "adddocuments",
  "add_documents",
  "addtexts",
  "add_texts",
  "upsert",
  "insert",
  "ingest",
  "embed",
  "indexdocuments",
  "index_documents",
  "fromtexts",
  "from_texts",
  "fromdocuments",
  "from_documents",
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
  "embeddings",
  "documentstore",
];

// Taint sources — request/user-derived data. Bare "body."/"query."/"params."
// deliberately excluded — see the comment on REQUEST_SOURCES in
// mcp-dynamic-server-url.ts for the false-positive class this caused (any
// function parameter conventionally named "params", not necessarily an HTTP
// request).
const REQUEST_SOURCES = ["req.", "request.", "ctx."];

function isVectorIngestionCall(node: Node): boolean {
  if (!Node.isCallExpression(node)) return false;
  const exprText = node.getExpression().getText().toLowerCase();
  return (
    VECTOR_STORE_CLIENTS.some((c) => exprText.includes(c)) &&
    INGESTION_METHODS.some((m) => exprText.endsWith(m))
  );
}

// Bare parameter names that conventionally hold the whole request/context
// object (matches the REQUEST_SOURCES prefixes above, minus the dot).
const REQUEST_PARAM_NAMES = new Set(["req", "request", "ctx"]);

function collectTaintedVars(fnNode: Node): Set<string> {
  const tainted = new Set<string>();

  if ("getParameters" in fnNode) {
    for (const param of (fnNode as any).getParameters()) {
      const nameNode = param.getNameNode?.();
      // Only a parameter that IS the request object (req, request, ctx) is
      // tainted by presence alone. Every other parameter used to be tainted
      // unconditionally, which flagged any ordinary batch/admin ingestion
      // function — e.g. `function importDocs(docs) { store.addDocuments(docs) }`
      // — purely because "docs" is a parameter, with no actual request-data
      // link. Real request-derived taint is still caught below via
      // REQUEST_SOURCES member-access on the initializer.
      if (nameNode && Node.isIdentifier(nameNode) && REQUEST_PARAM_NAMES.has(nameNode.getText().toLowerCase())) {
        tainted.add(nameNode.getText());
      }
    }
  }

  for (const decl of fnNode.getDescendantsOfKind(SyntaxKind.VariableDeclaration)) {
    const init = decl.getInitializer();
    if (!init) continue;
    const initText = init.getText();
    if (REQUEST_SOURCES.some((src) => initText.includes(src))) {
      tainted.add(decl.getName());
    }
    if (Node.isIdentifier(init) && tainted.has(init.getText())) {
      tainted.add(decl.getName());
    }
  }

  return tainted;
}

function userInputFlowsToIngestion(call: Node, tainted: Set<string>): boolean {
  if (!Node.isCallExpression(call)) return false;
  const argsText = call.getArguments().map((a) => a.getText()).join(" ");
  return (
    REQUEST_SOURCES.some((src) => argsText.includes(src)) ||
    [...tainted].some((v) => argsText.includes(v))
  );
}

export const ruleVecUserIngestion: Rule = {
  id: "VEC003",
  title: "User-controlled content ingested into vector store",
  severity: "high",
  run(context: RuleContext): Finding[] {
    const findings: Finding[] = [];

    for (const sourceFile of context.sourceFiles) {
      const relPath = getRelativeFilePath(context.rootPath, sourceFile);
      const isTest = isTestFilePath(relPath);

      for (const fnNode of sourceFile.getDescendants()) {
        if (
          !Node.isFunctionDeclaration(fnNode) &&
          !Node.isFunctionExpression(fnNode) &&
          !Node.isArrowFunction(fnNode) &&
          !Node.isMethodDeclaration(fnNode)
        ) continue;

        const tainted = collectTaintedVars(fnNode);
        const hasSanitization = hasSanitizationNearby(fnNode.getText());

        for (const call of fnNode.getDescendantsOfKind(SyntaxKind.CallExpression)) {
          if (!isVectorIngestionCall(call)) continue;
          if (!userInputFlowsToIngestion(call, tainted)) continue;
          if (hasSanitization) continue;

          findings.push({
            rule_id: "VEC003",
            title: "User-controlled content ingested into vector store",
            severity: "high",
            file: relPath,
            line: getNodeLine(call),
            summary: "User-supplied content is being stored in a vector database without sanitization.",
            description:
              "Allowing users to directly ingest content into a shared vector store is a training/retrieval data poisoning attack. A malicious user can plant documents containing prompt injection payloads. When those documents are later retrieved via similarity search, the injected instructions are silently executed by the LLM.",
            recommendation:
              "Validate and sanitize all user-provided content before ingestion. Isolate user-submitted documents in a quarantine namespace pending review. Consider scanning ingested content for injection patterns before making it available to retrieval pipelines.",
            confidence: evidenceConfidence(isTest ? demoteEvidence("likely") : "likely"),
            evidence: isTest ? demoteEvidence("likely") : "likely",
          });
        }
      }
    }

    return findings;
  },
};
