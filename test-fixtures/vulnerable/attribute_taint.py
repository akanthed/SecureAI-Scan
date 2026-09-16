"""Class-based handler: request data lands on an attribute, not a local.

This is the shape the line-oriented scanner could not see at all — the taint
target is `self.user_message`, and the LLM call is far enough away that no
proximity window reaches the request read.
"""

from flask.views import MethodView
from flask import request
from openai import OpenAI

client = OpenAI()


class ChatView(MethodView):
    def post(self):
        self.user_message = request.json["message"]
        self.request_id = request.json.get("id", "anon")

        # Ordinary business logic between the request read and the model call.
        self.audit_log = []
        self.audit_log.append(self.request_id)
        self.rate_limit_bucket = self.request_id[:8]
        self.started = True
        self.retry_count = 0
        self.model_name = "gpt-4o-mini"
        self.temperature = 0.2
        self.max_tokens = 512
        self.stop = None
        self.trace = {}
        self.trace["id"] = self.request_id
        self.trace["len"] = len(self.user_message)
        self.locale = "en-US"
        self.tenant = "acme"
        self.flags = {"beta": False}
        self.history = []
        self.history.append(self.user_message)
        self.prepared = f"Answer the user. Question: {self.user_message}"

        return client.chat.completions.create(
            model=self.model_name,
            messages=[{"role": "system", "content": self.prepared}],
        )
