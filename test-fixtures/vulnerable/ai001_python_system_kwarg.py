# Vulnerable: request data interpolated into Anthropic's `system=` keyword.
from fastapi import FastAPI, Request
from anthropic import Anthropic

app = FastAPI()
claude = Anthropic()


@app.post("/chat")
async def chat(request: Request):
    body = await request.json()
    r = claude.messages.create(
        model="claude-sonnet-4-5",
        max_tokens=1024,
        system=f"You help with {body['topic']}. House rules: {body['rules']}",
        messages=[{"role": "user", "content": body["q"]}],
    )
    return {"a": r.content[0].text}
