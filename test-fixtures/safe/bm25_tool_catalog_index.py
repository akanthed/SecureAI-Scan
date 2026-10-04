# Regression fixture: found scanning jlowin/fastmcp
# (fastmcp/server/transforms/search/bm25.py). An in-memory BM25 index over the
# server's own tool catalog was reported as VEC001 "vector search without a
# per-tenant filter" because `self._index.query(...)` matched a generic
# `index.query(` shape. No vector store is involved.
class _BM25Index:
    def build(self, documents):
        self.documents = documents

    def query(self, text, limit):
        return list(range(min(limit, len(self.documents))))


class ToolSearch:
    def __init__(self):
        self._index = _BM25Index()
        self._tools = []

    def search(self, tools, query, max_results=5):
        self._index.build([tool.description for tool in tools])
        indices = self._index.query(query, max_results)
        return [tools[i] for i in indices]
