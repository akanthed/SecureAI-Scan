"""Documentation that contains a vulnerable example, in a library that is safe.

SDK and framework sources routinely embed runnable snippets in docstrings and
comments. A line-oriented matcher reads those as live code: the snippet below
is a complete AI001 dataflow (request source -> prompt -> model call), an AI005
exec sink, and a VEC001 unfiltered search — none of which this module executes.

Origin of this shape: llama_index / langchain module docstrings.

Example:
    from flask import request
    from openai import OpenAI

    client = OpenAI()

    user_input = request.json["q"]
    prompt = "You are a helpful bot. " + user_input
    response = client.chat.completions.create(
        model="gpt-4o",
        messages=[{"role": "system", "content": prompt}],
    )
    eval(response.choices[0].message.content)
    docs = vectorstore.similarity_search(user_input, k=5)
"""

from openai import OpenAI

client = OpenAI()


def summarize(document: str) -> str:
    """Summarize an operator-supplied document.

    Usage:
        text = request.json["document"]
        client.chat.completions.create(model="gpt-4o", messages=[
            {"role": "system", "content": text},
        ])
    """
    # user_input = request.json["q"]  -- deliberately commented out
    result = client.chat.completions.create(
        model="gpt-4o",
        messages=[
            {"role": "system", "content": "Summarize the document."},
            {"role": "user", "content": document},
        ],
    )
    return result.choices[0].message.content
