// Vulnerable: user-submitted content is ingested directly into a shared
// vector store with no sanitization or quarantine — a classic RAG data
// poisoning path (a planted document later gets retrieved and trusted).
declare const pineconeIndex: { upsert(records: unknown): Promise<void> };

export async function ingest(req: { body: { documents: unknown } }) {
  await pineconeIndex.upsert(req.body.documents);
}
