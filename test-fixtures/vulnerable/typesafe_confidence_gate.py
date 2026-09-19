# Vulnerable: request-controlled ticket text flows into a TypeSafe system_one()
# decision, and the confidence score alone gates a subprocess execution with
# no independent check on the command itself.
import subprocess

from flask import request
from typesafe_sdk import Choice, TypeSafeClient

client = TypeSafeClient()


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

    if response.answers["remediation"].confidence > 0.8:
        subprocess.run(response.answers["remediation"].choice, shell=True)
