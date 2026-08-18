# Regression fixture: found scanning BerriAI/litellm. FastAPI's idiomatic
# per-route auth is a `Depends(...)` dependency injected via a parameter
# default (and/or the decorator's `dependencies=[...]` kwarg) — not a
# decorator by itself, and not something written in the function body.
# AI003 previously never looked at the parameter list at all.
import openai
from fastapi import APIRouter, Depends

router = APIRouter()


async def user_api_key_auth():
    ...


@router.get(
    "/health/services",
    dependencies=[Depends(user_api_key_auth)],
)
async def health_services_endpoint(
    user_api_key_dict=Depends(user_api_key_auth),
):
    client = openai.OpenAI()
    return client.chat.completions.create(
        model="gpt-4",
        messages=[{"role": "user", "content": "ping"}],
    )
