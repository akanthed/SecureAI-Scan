// Vulnerable: a generic `.query(` on a Pinecone index with no tenant filter.
// The Pinecone SDK import is what makes the generic method name evidence of a
// vector store (VEC001), and `.upsert(` without a namespace likewise (VEC004).
import { Pinecone } from "@pinecone-database/pinecone";

const pineconeIndex = new Pinecone().index("shared-kb");

export async function lookup(vector: number[]) {
  return pineconeIndex.query({ vector, topK: 5, includeMetadata: true });
}

export async function store(id: string, values: number[]) {
  await pineconeIndex.upsert([{ id, values }]);
}
