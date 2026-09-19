# Safe: same TypeSafe confidence-gated shape as the vulnerable fixture, but
# the remediation choice is checked against an allowlist before it is ever
# passed to subprocess.run — the confidence score alone is not treated as
# authorization.
import subprocess

from flask import request
from typesafe_sdk import Choice, TypeSafeClient

client = TypeSafeClient()

ALLOWLIST = {"restart": "systemctl restart my-service", "clear_cache": "rm -rf /var/cache/my-app/*"}


def handle_ticket():
    ticket_text = request.json["body"]

    response = client.system_one(
        state=ticket_text,
        questions={
            "remediation": Choice(
                instructions="Which remediation command should run?",
                criteria={"restart": "Restart the service", "clear_cache": "Clear the cache"},
            ),
        },
    )

    choice = response.answers["remediation"].choice
    if response.answers["remediation"].confidence > 0.8 and choice in ALLOWLIST:
        subprocess.run(ALLOWLIST[choice])
    else:
        escalate_to_human(ticket_text)
