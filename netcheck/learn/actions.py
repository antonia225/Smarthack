"""Safe, non-executing actions proposed by Learning Mode."""

from __future__ import annotations

import ipaddress
import json
import re
from typing import Any


_IP_OR_CIDR = re.compile(
    r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?:/\d{1,2})?(?![\d.])"
)
_SCAN_WORDS = re.compile(r"\b(scan|scanează|scaneaza|inspect|inspectează|inspecteaza)\b", re.I)
_NETWORK_WORDS = re.compile(
    r"\b(rețeaua mea|reteaua mea|rețeaua locală|reteaua locala|my network|local network)\b",
    re.I,
)


def _valid_target(value: Any) -> str | None:
    if not isinstance(value, str):
        return None
    if value == "local-network":
        return value
    try:
        if "/" not in value:
            return str(ipaddress.ip_address(value))
        return str(ipaddress.ip_network(value, strict=False))
    except ValueError:
        return None


def proposal_from_question(question: str) -> dict[str, str] | None:
    """Extract a scan proposal without executing or authorizing it."""

    if not _SCAN_WORDS.search(question):
        return None
    match = _IP_OR_CIDR.search(question)
    if match:
        target = _valid_target(match.group(0))
        if target:
            return {"action": "propose_scan", "target": target}
    if _NETWORK_WORDS.search(question):
        return {"action": "propose_scan", "target": "local-network"}
    return None


def proposal_from_answer(answer: str) -> dict[str, str] | None:
    """Accept only a strict JSON proposal returned by an AI provider."""

    decoder = json.JSONDecoder()
    for index, character in enumerate(answer):
        if character != "{":
            continue
        try:
            value, _ = decoder.raw_decode(answer[index:])
        except json.JSONDecodeError:
            continue
        if not isinstance(value, dict) or set(value) != {"action", "target"}:
            continue
        if value.get("action") != "propose_scan":
            continue
        target = _valid_target(value.get("target"))
        if target:
            return {"action": "propose_scan", "target": target}
    return None


def message(proposal: dict[str, str], lang: str) -> str:
    target = proposal["target"]
    if target == "local-network":
        target = "rețeaua locală" if lang == "ro" else "the local network"
    if lang == "ro":
        return f"Pot propune scanarea pentru {target}. Confirmă manual scanarea pentru a continua."
    return f"I can propose a scan of {target}. Confirm the scan manually to continue."
