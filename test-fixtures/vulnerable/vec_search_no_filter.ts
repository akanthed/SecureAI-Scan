// Vulnerable: a LangChain-style similarity search over a store shared by all
// users, with no namespace/filter scoped to the caller (VEC001).
declare const vectorStore: { similaritySearch(query: string, k: number): Promise<unknown[]> };

export async function answer(req: { user: { id: string }; body: { q: string } }) {
  return vectorStore.similaritySearch(req.body.q, 4);
}
