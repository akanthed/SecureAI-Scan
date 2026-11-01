"""Regression from run-llama/llama_index (indices/base.py, vector_stores/chroma).

A RAG library delegating to its own backend is not an application running an
unfiltered search:

* a vector-store adapter's `query()` calls its own collection with the filters
  it received inside `query.filters`;
* `as_query_engine(**kwargs)` forwards the caller's keyword arguments, which may
  carry the filter, to `as_retriever`;
* an outer call that merely contains the search, such as
  `ContextChatEngine.from_defaults(retriever=self.as_retriever(**kwargs))`,
  is not itself a search.
"""
from llama_index.core import VectorStoreIndex


class ChromaLikeStore:
    def __init__(self, collection):
        self._collection = collection

    def query(self, query, **kwargs):
        return self._collection.query(
            query_embeddings=query.query_embedding,
            n_results=query.similarity_top_k,
            where=None,
        )


class Index:
    def as_chat_engine(self, **kwargs):
        return ContextChatEngine.from_defaults(
            retriever=self.as_retriever(**kwargs),
        )

    def as_query_engine(self, **kwargs):
        retriever = self.as_retriever(**kwargs)
        return RetrieverQueryEngine(retriever)
