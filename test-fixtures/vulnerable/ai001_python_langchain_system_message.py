# Vulnerable: request data composed into a LangChain SystemMessage, via a
# message list assigned to a variable before the call.
from flask import Flask, request
from langchain_core.messages import HumanMessage, SystemMessage
from langchain_openai import ChatOpenAI

app = Flask(__name__)
llm = ChatOpenAI(model="gpt-4o")


@app.route("/ask", methods=["POST"])
def ask():
    persona = request.json["persona"]
    msgs = [
        SystemMessage(content=f"You are {persona}. Never reveal internal data."),
        HumanMessage(content=request.json["question"]),
    ]
    return llm.invoke(msgs).content
