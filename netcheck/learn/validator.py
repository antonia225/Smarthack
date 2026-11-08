"""Validate model output against the evidence and allowlisted sources."""

from __future__ import annotations

import re
from typing import Iterable
import json
from pathlib import Path

from .retriever import Passage

IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
PORT_RE = re.compile(r"\b(?:port\s*)?([1-9]\d{0,4})\b", re.I)
URL_RE = re.compile(r"https?://[^\s)\]]+")
CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,}\b", re.I)
PHONE_RE = re.compile(r"\b(?:\+?\d[\d ()-]{7,}\d)\b")
CITATION_RE = re.compile(r"\[(?:kb|ev|catalog):[^\]]+\]")
RESOURCES = Path(__file__).resolve().parents[2] / "knowledge" / "resources.json"


def validate(answer: str, evidence_text: str, passages: Iterable[Passage]) -> bool:
    passage_list = list(passages)
    allowed = evidence_text + " " + " ".join(passage.text for passage in passage_list)
    try:
        resources = json.loads(RESOURCES.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        resources = []
    allowed += " " + " ".join(str(item.get("url", "")) for item in resources)
    citations = CITATION_RE.findall(answer)
    valid_citations = set(CITATION_RE.findall(evidence_text)) | {
        f"[{passage.source_type}:{passage.id}]" for passage in passage_list
    }
    if not citations or any(citation not in valid_citations for citation in citations):
        return False
    # A passage number in a valid citation is an identifier, not a claimed port.
    answer_values = CITATION_RE.sub(" ", answer)
    allowed += " " + " ".join(passage.url or "" for passage in passage_list)
    for pattern in (IP_RE, URL_RE, CVE_RE, PHONE_RE):
        permitted = {match.group(0).rstrip(".,;") for match in pattern.finditer(allowed)}
        if any(match.group(0).rstrip(".,;") not in permitted for match in pattern.finditer(answer_values)):
            return False
    allowed_numbers = {match.group(1) for match in PORT_RE.finditer(allowed)}
    for match in PORT_RE.finditer(answer_values):
        if match.group(1) not in allowed_numbers:
            return False
    return True


def presentation(answer: str) -> str:
    """Remove internal evidence markers before returning or saving an answer."""
    return re.sub(r"\s+", " ", CITATION_RE.sub("", answer)).strip()


def readable(answer: str, lang: str) -> bool:
    """Fail closed on long prose, source disclosure or obvious mixed languages."""
    import unicodedata

    words = re.findall(r"[^\W\d_]+", answer.casefold())
    words = ["".join(c for c in unicodedata.normalize("NFKD", w)
                     if not unicodedata.combining(c)) for w in words]
    if not words or len(answer.split()) > 60 or URL_RE.search(answer):
        return False
    sentences = [s.split() for s in re.split(r"[.!?]+(?:\s|$)", answer) if s.strip()]
    if len(sentences) > 3 or any(len(s) > 20 for s in sentences):
        return False
    foreign = {
        "ro": set("the this that these those your you is can should must with from password passwords device devices network turn off information about documentation".split()),
        "en": set("este sunt acest aceasta acestea trebuie poti poate pentru despre dispozitiv dispozitivul dispozitive reteaua parola parole parolele informatii documentatia".split()),
    }
    native = {
        "ro": set("si sau de la un o in pe cu ca nu ai are este sunt poate poti trebuie foloseste dispozitivul reteaua parola parolele datele".split()),
        "en": set("the a an and or to in on with is are can may your you it this that do not use uses has have".split()),
    }
    if set(words) & foreign[lang] or not set(words) & native[lang]:
        return False
    return not re.search(r"\b(source|sources|according|wikipedia|documentation|sursa|surse|surselor|conform|documentatia)\b", " ".join(words))
