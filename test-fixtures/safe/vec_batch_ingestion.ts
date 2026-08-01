// Safe: an internal batch/admin ingestion job takes a plain parameter and
// passes it straight to the vector store — no request object anywhere in
// this file. VEC003 previously tainted every function parameter by
// presence alone, which flagged exactly this ordinary shape.
declare const pineconeIndex: { addDocuments(docs: unknown[]): Promise<void> };

export async function reindexFromNightlyExport(docs: unknown[]) {
  await pineconeIndex.addDocuments(docs, { namespace: "internal-nightly" });
}
