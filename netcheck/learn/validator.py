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
    if not CITATION_RE.search(answer):
        return False
    if any(match.group(0) not in allowed for pattern in (IP_RE, URL_RE, CVE_RE, PHONE_RE) for match in pattern.finditer(answer)):
        return False
    for match in PORT_RE.finditer(answer):
        value = match.group(1)
        if value not in allowed and match.group(0).strip().isdigit():
            return False
    return True
