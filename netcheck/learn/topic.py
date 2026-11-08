"""Topic gate: the assistant only answers about the scan and network security.

Deterministic and offline, so an off-topic question never reaches the LLM and
never retrieves unrelated documentation.
"""
from __future__ import annotations

import json
import re
import unicodedata
from typing import Any

from netcheck.catalog import load_catalog
from .retriever import KNOWLEDGE

_TOKEN = re.compile(r"[^\W_]+", re.UNICODE)
_IP = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")

# Exact words (accents removed) and stems for long, inflected words.
_WORDS = set("""
scan scans scanned network networks wifi router routers device devices port ports service services
password passwords risk risks safe safety secure security vulnerability vulnerabilities problem problems
fix fixes finding findings score result results severity camera printer hotspot firewall ip mac
hostname open closed exposed encryption encrypted update updates start first step steps hacker attack
retea retele dispozitiv dispozitive porturi portul portului porturile serviciu servicii parola parole
risc riscuri sigur sigura siguranta securitate vulnerabilitate vulnerabilitati problema probleme
repar rezultat rezultate scor severitate imprimanta deschis deschise inchis expus expusa criptat
actualizare actualizari incep incepe prim primul pas pasi atac telnet ssh ftp rdp vnc smb mqtt snmp
upnp http https rtsp dns tcp udp nat vpn wpa wpa2 wpa3 admin
""".split())
# Short follow-ups are only on topic when a device from the scan is selected.
_CONTEXT = set("""
inseamna mean means explica explain grav serious periculos dangerous danger why cum how rezolv solve help
ajuta ajutor important worry ingrijorat
""".split())
_STEMS = ("scanar", "vulnerab", "securit", "dispoziti", "imprimant", "remedi", "repar", "rezultat",
          "protej", "protect", "configur", "reteau", "retel")
_PHRASES = ("cu ce incep", "where do i start", "ce trebuie sa fac", "what should i do")

REFUSAL = {
    "ro": "Pot răspunde doar la întrebări despre această scanare și despre securitatea rețelei tale "
          "(dispozitive, porturi, probleme, pași de reparare). Încearcă o întrebare din această zonă.",
    "en": "I can only answer questions about this scan and your network's security "
          "(devices, ports, problems, how to fix them). Please try a question in that area.",
}


def _norm(text: str) -> str:
    return "".join(c for c in unicodedata.normalize("NFKD", text.casefold()) if not unicodedata.combining(c))


def _vocabulary() -> set[str]:
    words = set(_WORDS)
    try:
        for source in json.loads((KNOWLEDGE / "sources.json").read_text(encoding="utf-8")):
            for keyword in source.get("keywords_en", []) + source.get("keywords_ro", []):
                words.update(_TOKEN.findall(_norm(keyword)))
    except (OSError, ValueError, TypeError):
        pass
    try:
        for code in load_catalog():
            words.update(_TOKEN.findall(_norm(code)))
    except Exception:  # catalog problems are handled elsewhere; the static list still works
        pass
    return words


def is_on_topic(question: str, analysis: dict[str, Any] | None = None, *, has_device: bool = False) -> bool:
    text = _norm(question)
    if any(phrase in text for phrase in _PHRASES):
        return True
    if analysis and any(ip in {d.get("ip") for d in analysis.get("devices", [])} for ip in _IP.findall(text)):
        return True
    vocabulary = _vocabulary() | (_CONTEXT if has_device else set())
    return any(t in vocabulary or (len(t) >= 5 and t.startswith(_STEMS)) for t in _TOKEN.findall(text))
