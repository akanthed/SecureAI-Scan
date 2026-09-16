# Vulnerable: request data flows into an LLM call; user content ingested.
from flask import Flask, request
from openai import OpenAI

app = Flask(__name__)
client = OpenAI()


@app.route("/ask", methods=["POST"])
def ask():
    question = request.json["question"]
    prompt = f"You are a helpful bot. {question}"
    response = client.chat.completions.create(
        model="gpt-4.1",
        messages=[{"role": "system", "content": prompt}],
    )
    return response.choices[0].message.content
