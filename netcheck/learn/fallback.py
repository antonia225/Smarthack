"""Safe local answer path used whenever an AI answer is unavailable."""

from __future__ import annotations

from typing import Any

from netcheck.catalog import load_catalog
from .retriever import Passage, search, source_dict


PREFIX = {
    "ro": "Asistentul nu e disponibil acum; iată ce spune documentația: ",
    "en": "The assistant is not available right now; here is what the documentation says: ",
}


def answer(
    question: str,
    analysis: dict[str, Any],
    *,
    lang: str,
    device_ip: str | None = None,
) -> tuple[str, list[dict[str, str | None]]]:
    passages = search(question, lang=lang)
    if device_ip:
        selected = [
            finding for finding in analysis.get("findings", [])
            if finding.get("ip") == device_ip
        ]
        if selected:
            catalog = load_catalog()
            code = str(selected[0]["code"])
            passage = Passage(
                code,
                str(catalog[code]["title"][lang]),
                str(catalog[code]["explain"][lang]),
                "catalog",
            )
            passages = [passage] + [item for item in passages if item.id != code]
    if not passages:
        message = {
            "ro": "Scanarea nu poate răspunde la această întrebare.",
            "en": "The scan cannot answer that question.",
        }[lang]
        return PREFIX[lang] + message + " [catalog:local]", [
            {"type": "catalog", "id": "local", "title": "Local catalog"}
        ]
    selected = passages[:2]
    answer_text = " ".join(item.text for item in selected)
    citations = " ".join(
        f"[{item.source_type}:{item.id}]" for item in selected
    )
    return PREFIX[lang] + answer_text + " " + citations, [
        source_dict(item) for item in selected
    ]
