// Vulnerable: the vector search result count (k) is taken directly from
// request input — an attacker can force retrieval of thousands of documents
// per request (prompt-stuffing / cost exhaustion / cross-tenant exposure).
declare const vectorStore: { similaritySearch(query: string, k: number): Promise<unknown[]> };

export async function search(req: { query: { q: string; k: string } }) {
  return vectorStore.similaritySearch(req.query.q, req.query.k as unknown as number);
}
