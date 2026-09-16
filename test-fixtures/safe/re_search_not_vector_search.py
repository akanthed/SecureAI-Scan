"""Found scanning BerriAI/litellm's http_parsing_utils.py: re.search() with a
regex pattern string that happens to contain "vector" is stdlib regex, not a
vector-store similarity search. VEC001 must not fire on this.
"""
import re


def populate_request_with_path_params(request_data, path):
    vector_store_match = re.search(r"/vector_stores/([^/]+)/", path)
    if vector_store_match:
        vector_store_id = vector_store_match.group(1)
        request_data.setdefault("vector_store_id", vector_store_id)
