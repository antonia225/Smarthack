"""Minimal OpenAI-compatible provider adapter with a short timeout."""

from __future__ import annotations

import json
import os
from urllib.request import Request, urlopen


class AgentError(RuntimeError):
    """The configured provider could not produce a response."""


def ask(prompt: str) -> str:
    key = os.environ.get("NETCHECK_LLM_API_KEY")
    model = os.environ.get("NETCHECK_LLM_MODEL")
    if not key or not model:
        raise AgentError("LLM credentials are not configured")
    instructions, _, data = prompt.partition("\n\n")
    payload = json.dumps({
        "model": model,
        "messages": [{"role": "system", "content": instructions},
                     {"role": "user", "content": data}],
        "max_tokens": 240,
        "temperature": 0,
    }).encode("utf-8")
    request = Request(
        os.environ.get("NETCHECK_LLM_API_URL", "https://api.openai.com/v1/chat/completions"),
        data=payload,
        headers={"Authorization": f"Bearer {key}", "Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urlopen(request, timeout=8) as response:
            data = json.loads(response.read(1_000_000))
        content = data["choices"][0]["message"]["content"]
    except (OSError, KeyError, IndexError, TypeError, ValueError) as exc:
        raise AgentError("LLM request failed") from exc
    if not isinstance(content, str) or not content.strip():
        raise AgentError("LLM returned an empty answer")
    return content.strip()
