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
# Only complete, neutral follow-ups inherit the selected device's context.
# A word such as "cum"/"how" alone never makes an unrelated question relevant.
_FOLLOWUPS = set("""
ce inseamna|ce inseamna asta|ce inseamna acest lucru|explica|explica mi|explica asta|
explica mi asta|este grav|e grav|este periculos|e periculos|de ce|cum|cum fac|
cum fac asta|cum rezolv|cum rezolv asta|ce pot face|ma poti ajuta|
what does this mean|what does it mean|explain|explain this|is it serious|
is this dangerous|why|how|how do i do that|how do i fix it|can you help
""".replace("\n", "").split("|"))
# Words from multi-word keywords and finding codes are not topic evidence alone.
_GENERIC = set("""
de la and the a an in on to for of si cu pe din un o este e ce cum how what
open closed exposed cleartext unknown outdated first start step steps prim primul pas pasi
safe safety secure sigur sigura siguranta important help fix fixes problem problems problema probleme
name nume date text string sir default implicita local locale control public
""".split())
_STEMS = ("scanar", "vulnerab", "securit", "dispoziti", "imprimant", "remedi", "repar", "rezultat",
          "protej", "protect", "configur", "reteau", "retel")
_PHRASES = ("cu ce incep", "where do i start", "ce trebuie sa fac", "what should i do")

REFUSAL = {
    "ro": "Nu am informații despre asta în documentația mea.",
    "en": "I do not have information about that in my documentation.",
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
    return words - _GENERIC


def is_on_topic(question: str, analysis: dict[str, Any] | None = None, *, has_device: bool = False) -> bool:
    text = _norm(question)
    normalized_question = " ".join(_TOKEN.findall(text))
    # Intent detection uses broad patterns; only a complete neutral question
    # may inherit scan context without an explicit network topic.
    neutral_intents = {
        "care e scorul meu", "ce scor am", "explica mi scorul", "cum se calculeaza scorului",
        "care dispozitiv e cel mai periculos", "care e cea mai grava problema",
        "ce inseamna asta", "ce inseamna", "e grav", "cat de grav e", "cum repar",
        "cum il repar", "cum repar cea mai grava problema",
        "what is my score", "which device is the most dangerous", "what does this mean",
        "is it bad", "is this serious", "how do i fix it",
    }
    if normalized_question in _PHRASES or normalized_question in neutral_intents:
        return True
    if analysis and any(ip in {d.get("ip") for d in analysis.get("devices", [])} for ip in _IP.findall(text)):
        return True
    if has_device and normalized_question in _FOLLOWUPS:
        return True
    vocabulary = _vocabulary()
    return any(t in vocabulary or (len(t) >= 5 and t.startswith(_STEMS)) for t in _TOKEN.findall(text))
