"""Validated local explanations; never a source of scan decisions."""
from __future__ import annotations

from copy import deepcopy
from functools import lru_cache
import json
from pathlib import Path
import re
from typing import Any

CATALOG_PATH = Path(__file__).with_name("catalog.json")
_EXPECTED = {
    **dict.fromkeys(("TELNET_OPEN", "RDP_EXPOSED", "VNC_EXPOSED", "DB_EXPOSED",
                     "CAMERA_STREAM_EXPOSED", "OUTDATED_SERVICE"), ("high", 20)),
    **dict.fromkeys(("FTP_CLEARTEXT", "HTTP_ADMIN_CLEARTEXT", "SMB_EXPOSED",
                     "MQTT_EXPOSED", "UPNP_EXPOSED", "SNMP_EXPOSED"), ("medium", 10)),
    "PRINTER_RAW_EXPOSED": ("low", 5),
    "UNKNOWN_DEVICE": ("low", 5),
    "SSH_OPEN": ("info", 0),
}


class CatalogError(ValueError):
    """Missing or invalid local explanation catalog."""


def _validate(data: Any) -> None:
    if not isinstance(data, dict) or set(data) != set(_EXPECTED):
        raise ValueError("expected exactly 15 finding codes")
    for code, entry in data.items():
        if not isinstance(entry, dict) or set(entry) != {"severity", "points", "title", "explain", "fix"}:
            raise ValueError(f"invalid fields: {code}")
        if type(entry["points"]) is not int or (entry["severity"], entry["points"]) != _EXPECTED[code]:
            raise ValueError(f"invalid severity/points: {code}")
        for field in ("title", "explain", "fix"):
            localized = entry[field]
            if not isinstance(localized, dict) or set(localized) != {"ro", "en"}:
                raise ValueError(f"missing languages: {code}.{field}")
            for lang, value in localized.items():
                values = value if field == "fix" else [value]
                if field == "fix" and (not isinstance(value, list) or not 1 <= len(value) <= 5):
                    raise ValueError(f"expected 1–5 steps: {code}.{lang}")
                if any(not isinstance(text, str) or not text.strip() or "CVE-" in text.upper() for text in values):
                    raise ValueError(f"invalid text: {code}.{field}.{lang}")
                if field == "explain" and len([s for s in re.split(r"[.!?]+", value) if s.strip()]) > 2:
                    raise ValueError(f"expected at most two sentences: {code}.{lang}")


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate catalog key")
        result[key] = value
    return result


@lru_cache(maxsize=1)
def _read_catalog() -> dict[str, Any]:
    try:
        data = json.loads(CATALOG_PATH.read_text(encoding="utf-8"), object_pairs_hook=_unique_object)
        _validate(data)
        return data
    except (OSError, ValueError) as exc:
        raise CatalogError(
            "Catalogul de explicații lipsește sau este invalid. Restaurează catalog.json. / "
            "The explanation catalog is missing or invalid. Restore catalog.json."
        ) from exc


def load_catalog() -> dict[str, Any]:
    """Read and validate once; return a copy to protect the cached content."""
    return deepcopy(_read_catalog())


def attach_explanations(analysis: dict[str, Any], lang: str | None = None) -> dict[str, Any]:
    """Decorate findings without changing the engine model or stored history."""
    catalog = load_catalog()
    result = deepcopy(analysis)
    for finding in result.get("findings", []):
        entry = catalog[finding["code"]]
        for field in ("title", "explain", "fix"):
            finding[field] = entry[field] if lang is None else entry[field][lang]
    return result
