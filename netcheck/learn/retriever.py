"""Small deterministic BM25 retriever for local knowledge and catalog text."""

from __future__ import annotations

from dataclasses import dataclass
import json
from math import log
from pathlib import Path
import re
from typing import Any

from netcheck.catalog import load_catalog

ROOT = Path(__file__).resolve().parents[2]
KNOWLEDGE = ROOT / "knowledge"
TOKEN_RE = re.compile(r"[^\W_]+", re.UNICODE)


@dataclass(frozen=True)
class Passage:
    id: str
    title: str
    text: str
    source_type: str
    url: str | None = None


def _tokens(text: str) -> list[str]:
    return [token.casefold() for token in TOKEN_RE.findall(text)]


def _front_matter(path: Path) -> tuple[dict[str, str], str]:
    content = path.read_text(encoding="utf-8")
    if not content.startswith("---\n"):
        return {}, content
    _, header, body = content.split("---\n", 2)
    values: dict[str, str] = {}
    for line in header.splitlines():
        if ":" in line:
            key, value = line.split(":", 1)
            values[key.strip()] = value.strip()
    return values, body.strip()


def _knowledge_passages() -> list[Passage]:
    passages: list[Passage] = []
    for path in sorted(KNOWLEDGE.glob("*.md")):
        if path.name == "README.md":
            continue
        metadata, body = _front_matter(path)
        if body:
            passages.append(
                Passage(
                    id=path.stem,
                    title=path.stem.replace("-", " ").title(),
                    text=body,
                    source_type="kb",
                    url=metadata.get("source_url"),
                )
            )
    return passages


def _catalog_passages(lang: str) -> list[Passage]:
    passages: list[Passage] = []
    for code, entry in sorted(load_catalog().items()):
        title = str(entry["title"][lang])
        explanation = str(entry["explain"][lang])
        fixes = " ".join(str(step) for step in entry["fix"][lang])
        passages.append(Passage(code, title, f"{title}. {explanation} {fixes}", "catalog"))
    return passages


def passages(lang: str = "ro") -> list[Passage]:
    return _knowledge_passages() + _catalog_passages(lang)


def search(question: str, *, lang: str = "ro", limit: int = 4) -> list[Passage]:
    query = _tokens(question)
    if not query:
        return []
    documents = passages(lang)
    tokenized = [_tokens(document.text) for document in documents]
    average_length = sum(len(tokens) for tokens in tokenized) / max(1, len(tokenized))
    document_frequency: dict[str, int] = {}
    for tokens in tokenized:
        for token in set(tokens):
            document_frequency[token] = document_frequency.get(token, 0) + 1
    scored: list[tuple[float, int, Passage]] = []
    for index, (document, tokens) in enumerate(zip(documents, tokenized)):
        frequencies = {token: tokens.count(token) for token in set(tokens)}
        score = 0.0
        for token in query:
            frequency = frequencies.get(token, 0)
            if not frequency:
                continue
            idf = log((len(documents) - document_frequency.get(token, 0) + 0.5) /
                      (document_frequency.get(token, 0) + 0.5) + 1)
            denominator = frequency + 1.5 * (0.25 + 0.75 * len(tokens) / max(1, average_length))
            score += idf * frequency * 2.5 / denominator
        if score:
            scored.append((score, index, document))
    scored.sort(key=lambda item: (-item[0], item[1]))
    return [document for _, _, document in scored[:limit]]


def source_dict(passage: Passage) -> dict[str, str | None]:
    result: dict[str, str | None] = {
        "type": passage.source_type,
        "id": passage.id,
        "title": passage.title,
    }
    if passage.url:
        result["url"] = passage.url
    return result
