// Safe: the retrieval depth comes from an operator-set environment variable,
// not from the request. `process.env` is configuration, not attacker input
// (VEC002 treated it as a user-controlled taint source).
declare const vectorStore: {
  similaritySearch(query: string, k: number, options: { filter: { tenantId: string } }): Promise<unknown[]>;
};

export async function search(query: string, tenantId: string) {
  return vectorStore.similaritySearch(query, Number(process.env.RETRIEVAL_K ?? "5"), { filter: { tenantId } });
}
