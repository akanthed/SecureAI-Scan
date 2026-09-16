// Vulnerable: documents are ingested into the vector store with no
// namespace/tenant/owner tag, so the read-side access-control filter (VEC001)
// has nothing to key on — this is the write-side half of that gap.
declare const pineconeIndex: { addDocuments(docs: unknown[]): Promise<void> };

export async function indexKnowledgeBase(docs: unknown[]) {
  await pineconeIndex.addDocuments(docs);
}
