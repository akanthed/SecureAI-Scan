# Regression fixture: an ordinary pydantic Field() description that happens
# to contain the words "system prompt" is unrelated config documentation,
# not metadata received from an external listing call.
from pydantic import BaseModel, Field


class AgentConfig(BaseModel):
    system_prompt: str = Field(
        default=None, description="The system prompt for the agent"
    )
