"""Catalog coverage, engine parity, localization and failure handling."""
import ast
import inspect
import json
import re

import pytest

from netcheck import catalog, rules


def engine_severities():
    # Include both service-table rules and direct _finding calls, so a new
    # engine code cannot silently escape catalog coverage.
    mapping = dict(rules._SERVICE_RULES.values())
    for node in ast.walk(ast.parse(inspect.getsource(rules))):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "_finding":
            if len(node.args) >= 4 and isinstance(node.args[2], ast.Constant):
                mapping[node.args[2].value] = node.args[3].value
    return mapping


def test_exact_codes_and_engine_points():
    data = catalog.load_catalog()
    mapping = engine_severities()
    assert len(data) == len(mapping) == 15
    assert data.keys() == mapping.keys()
    for code, severity in mapping.items():
        assert data[code]["severity"] == severity
        assert data[code]["points"] == rules.SEVERITY_POINTS[severity]


def test_bilingual_text_constraints():
    for entry in catalog.load_catalog().values():
        for field in ("title", "explain", "fix"):
            assert set(entry[field]) == {"ro", "en"}
        for lang in ("ro", "en"):
            assert entry["title"][lang].strip()
            assert 1 <= len([s for s in re.split(r"[.!?]+", entry["explain"][lang]) if s.strip()]) <= 2
            assert 1 <= len(entry["fix"][lang]) <= 5
            assert all(step.strip() for step in entry["fix"][lang])
        assert "CVE-" not in json.dumps(entry).upper()


@pytest.fixture
def isolated_catalog(monkeypatch, tmp_path):
    path = tmp_path / "catalog.json"
    data = catalog.load_catalog()
    catalog._read_catalog.cache_clear()
    monkeypatch.setattr(catalog, "CATALOG_PATH", path)
    yield path, data
    catalog._read_catalog.cache_clear()


@pytest.mark.parametrize("fault", ["missing", "json", "duplicate", "codes", "severity", "points", "languages", "sentences", "steps", "empty", "cve"])
def test_invalid_catalog_has_bilingual_error(isolated_catalog, fault):
    path, data = isolated_catalog
    entry = data["TELNET_OPEN"]
    if fault == "json": path.write_text("{")
    elif fault == "duplicate": path.write_text('{"x":1,"x":2}')
    elif fault != "missing":
        if fault == "codes": data.pop("SSH_OPEN")
        elif fault == "severity": entry["severity"] = "low"
        elif fault == "points": entry["points"] = True
        elif fault == "languages": entry["title"].pop("en")
        elif fault == "sentences": entry["explain"]["ro"] = "Unu. Doi. Trei."
        elif fault == "steps": entry["fix"]["en"] = []
        elif fault == "empty": entry["fix"]["ro"] = [" "]
        elif fault == "cve": entry["title"]["en"] = "CVE-1234"
        path.write_text(json.dumps(data))
    with pytest.raises(catalog.CatalogError, match="Catalogul.* / The explanation catalog"):
        catalog.load_catalog()


def test_reads_once_and_callers_cannot_mutate_cache(isolated_catalog):
    path, data = isolated_catalog
    path.write_text(json.dumps(data))
    loaded = catalog.load_catalog()
    loaded["TELNET_OPEN"]["fix"]["ro"].clear()
    path.unlink()
    assert catalog.load_catalog() == data
