// Safe: an in-memory keyword index over the server's own tool catalog that
// happens to be called `vectorStore`. `.search`/`.query`/`.upsert` are generic
// verbs, and nothing in this file imports a vector-store SDK, so they are not
// evidence of a vector database (VEC001/VEC004 must not report at likely).
declare function buildKeywordIndex(items: string[]): {
  search(term: string): string[];
  upsert(item: string): void;
};

const vectorStore = buildKeywordIndex(["list_files", "read_file"]);

export function findTool(term: string) {
  return vectorStore.search(term);
}

export function registerTool(name: string) {
  vectorStore.upsert(name);
}
