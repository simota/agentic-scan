"""Synthetic example for prompt-scan: deliberately contains prompt defects."""
import json
from pathlib import Path

from anthropic import Anthropic
from jinja2 import Template

PROMPTS = Path(__file__).parent / "prompts"
client = Anthropic()


def answer(ticket_body, question, documents):
    system = (PROMPTS / "support_system.md").read_text().format(ticket_body=ticket_body)
    user = Template((PROMPTS / "answer.prompt").read_text()).render(question=question)
    message = client.messages.create(
        model="claude-haiku-5-5",
        max_tokens=200,
        temperature=1.0,
        system=system,
        messages=[{"role": "user", "content": user}],
    )
    data = json.loads(message.content[0].text)
    return data["response"], data.get("sources", [])
