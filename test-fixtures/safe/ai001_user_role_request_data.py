# Regression fixture: the exact pattern AI001's own fix recommends — a static
# system prompt with request data confined to user-role messages. Python AI001
# used to fire HIGH/likely on any request data reaching any LLM call, with no
# regard for which role it landed in (found in a blind audit, 2026-10).
from fastapi import Depends, FastAPI, Request
from anthropic import Anthropic
from langchain_core.messages import HumanMessage, SystemMessage
from langchain_openai import ChatOpenAI
from openai import OpenAI

app = FastAPI()
client = OpenAI()
claude = Anthropic()
llm = ChatOpenAI(model="gpt-4o")
SYSTEM_PROMPT = "You are a helpful assistant."


async def require_user():
    ...


@app.post("/chat", dependencies=[Depends(require_user)])
async def chat(request: Request):
    body = await request.json()
    question = body["q"][:2000]
    r = client.chat.completions.create(
        model="gpt-4o",
        max_tokens=500,
        messages=[
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": question},
        ],
    )
    return {"a": r.choices[0].message.content}


@app.post("/claude", dependencies=[Depends(require_user)])
async def claude_chat(request: Request):
    body = await request.json()
    history = [{"role": "user", "content": f"Question: {body['q']}"}]
    r = claude.messages.create(
        model="claude-sonnet-4-5",
        max_tokens=500,
        system=SYSTEM_PROMPT,
        messages=history,
    )
    return {"a": r.content[0].text}


@app.post("/lc", dependencies=[Depends(require_user)])
async def langchain_chat(request: Request):
    body = await request.json()
    return llm.invoke([SystemMessage(content=SYSTEM_PROMPT), HumanMessage(content=body["q"])])


@app.post("/bare", dependencies=[Depends(require_user)])
async def bare_prompt(request: Request):
    body = await request.json()
    # A bare user string as the whole prompt has no instructions to override.
    return llm.invoke(body["q"])
