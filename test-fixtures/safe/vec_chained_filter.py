"""Regression from run-llama/llama_index's LanceDB vector-store adapter.

The search builder receives its tenant/document filter through a later fluent
`.where(where)` call. Looking only at the initial `.search(...)` node reports a
false missing-filter finding even though both calls mutate the same query.
"""


def search_table(table, query, where):
    lance_query = table.search(
        query=query.query_embedding,
        vector_column_name="embedding",
    )
    lance_query.limit(query.similarity_top_k).where(where)
    return lance_query.to_list()
