"""Vulnerable: an application endpoint searches a vector store shared by all
users with no filter scoped to the caller (VEC001)."""
from flask import Flask, request
from langchain_community.vectorstores import Chroma

app = Flask(__name__)
store = Chroma(collection_name="shared-kb")


@app.post("/ask")
def ask():
    question = request.json["q"]
    return {"docs": store.similarity_search(question, k=4)}
