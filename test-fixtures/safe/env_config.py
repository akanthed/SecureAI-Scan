# Safe: reading the API key from the environment next to an LLM client is
# normal configuration, not user input.
# (Regression fixture: os.environ used to count as a prompt-injection source.)
import os

from openai import OpenAI

api_key = os.environ.get("OPENAI_API_KEY")
client = OpenAI(api_key=api_key)

SYSTEM_PROMPT = "You are a helpful assistant."


def summarize(text: str) -> str:
    response = client.chat.completions.create(
        model="gpt-4.1",
        messages=[
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": text},
        ],
    )
    return response.choices[0].message.content
