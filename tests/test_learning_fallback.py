"""Offline Learning Mode answers built from the saved scan (no LLM, no network)."""

from collections import Counter
from copy import deepcopy
import json
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from netcheck import api, history
from netcheck.catalog import attach_explanations, load_catalog
from netcheck.learn import fallback, intent, retriever
from netcheck.scoring import analyze_file

VALIDATION = Path(__file__).parent / "validation"
SOURCES = json.loads((Path(__file__).parents[1] / "knowledge" / "sources.json").read_text(encoding="utf-8"))
LANGUAGE = {source["id"]: source["language"] for source in SOURCES}
CATALOG = load_catalog()

QUESTIONS = {
    "ro": {
        intent.WORST: "Care dispozitiv e cel mai periculos?",
        intent.START: "Cu ce încep?",
        intent.EXPLAIN: "Ce înseamnă asta?",
        intent.FIX: "Cum repar?",
        intent.SCORE: "Care e scorul meu?",
        intent.SEVERITY: "E grav?",
    },
    "en": {
        intent.WORST: "Which device is the most dangerous?",
        intent.START: "Where do I start?",
        intent.EXPLAIN: "What does this mean?",
        intent.FIX: "How do I fix it?",
        intent.SCORE: "What is my score?",
        intent.SEVERITY: "Is it bad?",
    },
}
CASES = [(lang, name, question) for lang, items in QUESTIONS.items() for name, question in items.items()]


@pytest.fixture
def offline(monkeypatch):
    """No provider credentials, and any provider or network use fails the test."""

    monkeypatch.delenv("NETCHECK_LLM_API_KEY", raising=False)
    monkeypatch.delenv("NETCHECK_LLM_MODEL", raising=False)
    monkeypatch.setattr("netcheck.learn.agent.urlopen", lambda *a, **k: pytest.fail("network used"))


def _client(monkeypatch, tmp_path, name="V4_legacy.xml"):
    monkeypatch.setattr(history, "DB_PATH", tmp_path / "learn.db")
    scan = analyze_file(VALIDATION / name)
    return TestClient(api.app), history.save_scan(scan), scan


def _ask(client, scan_id, question, lang, device_ip=None):
    body = {"scan_id": scan_id, "question": question, "lang": lang}
    if device_ip:
        body["device_ip"] = device_ip
    response = client.post("/api/ask", json=body)
    assert response.status_code == 200
    return response.json()


@pytest.mark.parametrize("lang,expected,question", CASES)
def test_intents_are_recognized_in_both_languages(lang, expected, question):
    assert intent.detect(question) == expected


@pytest.mark.parametrize("question,expected", [
    ("care e scorul meu", intent.SCORE), ("Ce scor am?", intent.SCORE), ("Explică-mi scorul", intent.SCORE),
    ("Cum se calculează scorului?", intent.SCORE), ("cu ce incep", intent.START),
    ("CE ÎNSEAMNĂ?", intent.EXPLAIN), ("Ce înseamnă rezultatele?", intent.EXPLAIN),
    ("Cât de grav e?", intent.SEVERITY), ("Is this serious?", intent.SEVERITY),
    ("Cum îl repar?", intent.FIX), ("Cum repar cea mai gravă problemă?", intent.FIX),
    ("Care e cea mai gravă problemă?", intent.WORST), ("Ce porturi sunt deschise?", intent.PORTS),
    ("Care e capitala Franței?", None), ("Explică-mi cum se face o prăjitură", None), ("Cât face 2+2?", None),
])
def test_intent_variants(question, expected):
    assert intent.detect(question) == expected


@pytest.mark.parametrize("lang,name,question", CASES)
@pytest.mark.parametrize("with_device", [False, True])
def test_every_intent_answers_from_the_scan(monkeypatch, tmp_path, offline, lang, name, question, with_device):
    client, scan_id, scan = _client(monkeypatch, tmp_path)
    device_ip = scan["top_risk"]["ip"] if with_device else None
    result = _ask(client, scan_id, question, lang, device_ip)

    assert result["mode"] == "fallback"
    assert result["answer"].startswith(fallback.PREFIX["scan"][lang])
    assert "nu e disponibil" not in result["answer"] and "not available" not in result["answer"]
    assert result["sources"][0]["type"] == "scan"
    saved = client.get(f"/api/scans/{scan_id}/answers").json()
    assert saved[-1]["answer"] == result["answer"] and saved[-1]["mode"] == "fallback"


@pytest.mark.parametrize("lang", ["ro", "en"])
def test_most_dangerous_device_is_the_engine_top_risk(monkeypatch, tmp_path, offline, lang):
    client, scan_id, scan = _client(monkeypatch, tmp_path)
    top = scan["top_risk"]
    answer = _ask(client, scan_id, QUESTIONS[lang][intent.WORST], lang)["answer"]
    assert top["ip"] in answer
    assert CATALOG[top["code"]]["title"][lang] in answer
    assert CATALOG[top["code"]]["fix"][lang][0] in answer


@pytest.mark.parametrize("lang", ["ro", "en"])
@pytest.mark.parametrize("with_device", [False, True])
def test_fix_lists_numbered_catalog_steps_in_the_requested_language(monkeypatch, tmp_path, offline, lang, with_device):
    client, scan_id, scan = _client(monkeypatch, tmp_path)
    device_ip = "192.168.1.1" if with_device else None
    answer = _ask(client, scan_id, QUESTIONS[lang][intent.FIX], lang, device_ip)["answer"]
    findings = [f for f in scan["findings"] if device_ip is None or f["ip"] == device_ip]
    first = next(f for f in findings if (f["ip"], f["code"]) == (scan["top_risk"]["ip"], scan["top_risk"]["code"]))
    for number, step in enumerate(CATALOG[first["code"]]["fix"][lang], 1):
        assert f"{number}. {step}" in answer
    other = "en" if lang == "ro" else "ro"
    assert CATALOG[first["code"]]["fix"][other][0] not in answer


def test_fix_for_selected_device_covers_its_findings(monkeypatch, tmp_path, offline):
    client, scan_id, scan = _client(monkeypatch, tmp_path)
    answer = _ask(client, scan_id, "Cum repar?", "ro", "192.168.1.1")["answer"]
    own = [f for f in scan["findings"] if f["ip"] == "192.168.1.1"]
    assert own
    for finding in own[:3]:
        for step in CATALOG[finding["code"]]["fix"]["ro"]:
            assert step in answer
    assert all(f["ip"] == "192.168.1.1" or f["ip"] not in answer for f in scan["findings"])


@pytest.mark.parametrize("question,lang,phrase", [
    ("Care e scorul meu?", "ro", "{score} din 100"), ("What is my score?", "en", "{score} out of 100"),
])
def test_score_question_reports_stored_score_and_counts(monkeypatch, tmp_path, offline, question, lang, phrase):
    client, scan_id, scan = _client(monkeypatch, tmp_path)
    result = _ask(client, scan_id, question, lang)
    assert result["mode"] == "fallback"
    assert phrase.format(score=scan["network_score"]) in result["answer"]
    counts = Counter(f["severity"] for f in scan["findings"])
    label = {"ro": "Ridicată", "en": "High"}[lang]
    assert f"{label} {counts['high']}" in result["answer"]


@pytest.mark.parametrize("question,lang", [
    ("Care e scorul meu?", "ro"), ("E grav?", "ro"), ("Ce înseamnă asta?", "ro"),
    ("Is it bad?", "en"), ("What does this mean?", "en"), ("What is my score?", "en"),
])
def test_short_scan_questions_are_accepted_without_a_device(monkeypatch, tmp_path, offline, question, lang):
    client, scan_id, _ = _client(monkeypatch, tmp_path)
    assert _ask(client, scan_id, question, lang)["mode"] == "fallback"


@pytest.mark.parametrize("lang,label", [("ro", "severitate ridicată"), ("en", "high severity")])
def test_is_it_bad_uses_the_top_finding_severity(monkeypatch, tmp_path, offline, lang, label):
    client, scan_id, scan = _client(monkeypatch, tmp_path)
    answer = _ask(client, scan_id, QUESTIONS[lang][intent.SEVERITY], lang)["answer"]
    assert scan["top_risk"]["severity"] == "high"
    assert label in answer
    assert CATALOG[scan["top_risk"]["code"]]["explain"][lang] in answer


def test_explain_selected_device_uses_catalog_explanations(monkeypatch, tmp_path, offline):
    client, scan_id, scan = _client(monkeypatch, tmp_path)
    answer = _ask(client, scan_id, "What does this mean?", "en", "192.168.1.1")["answer"]
    for finding in [f for f in scan["findings"] if f["ip"] == "192.168.1.1"][:3]:
        assert CATALOG[finding["code"]]["explain"]["en"] in answer


def test_clean_scan_has_nothing_to_fix(monkeypatch, tmp_path, offline):
    client, scan_id, scan = _client(monkeypatch, tmp_path, "V6b_after.xml")
    assert scan["findings"] == [] and scan["top_risk"] is None
    assert "100 din 100" in _ask(client, scan_id, "Care e scorul meu?", "ro")["answer"]
    assert "nimic de reparat" in _ask(client, scan_id, "Cum repar?", "ro")["answer"]
    assert "no findings" in _ask(client, scan_id, "Is it bad?", "en")["answer"]


@pytest.mark.parametrize("question", [
    *QUESTIONS["ro"].values(), "Ce este UPNP?", "Ce porturi sunt deschise?", "Ce riscuri are rețeaua?",
    "Este sigur că imprimanta are portul 9100 deschis?",
])
@pytest.mark.parametrize("with_device", [False, True])
def test_romanian_answers_contain_no_other_language_corpus(monkeypatch, tmp_path, offline, question, with_device):
    client, scan_id, scan = _client(monkeypatch, tmp_path, "V2_smart_home.xml")
    result = _ask(client, scan_id, question, "ro", scan["top_risk"]["ip"] if with_device else None)
    kb = [source for source in result["sources"] if source["type"] == "kb"]
    assert all(LANGUAGE[source["id"].split("#")[0]] == "ro" for source in kb)
    for phrase in ("width and height", "fingerprint", "Client Tracking", "The device", "...."):
        assert phrase not in result["answer"]


def test_english_answer_adds_one_clean_documented_excerpt(monkeypatch, tmp_path, offline):
    client, scan_id, scan = _client(monkeypatch, tmp_path)
    result = _ask(client, scan_id, "Which device is the most dangerous?", "en")
    kb = [source for source in result["sources"] if source["type"] == "kb"]
    assert len(kb) == 1 and kb[0]["url"].startswith("https://")
    passage = next(p for p in retriever.passages("en") if p.source_type == "kb" and p.id == kb[0]["id"])
    assert scan["top_risk"]["code"] in passage.codes
    assert f"[kb:{passage.id}]" in result["answer"]


def test_excerpt_cleaning_drops_fragments_and_tables_of_contents():
    toc = "Client Tracking Prevention ................................ 137 C.5 . Unauthenticated Operation"
    assert fallback.clean_excerpt(toc) is None
    text = ("width and height of the window available. The result is that the page is boxed. "
            "Chrome was not blocking fingerprinting in that year, while others did. Blocking scripts")
    cleaned = fallback.clean_excerpt(text)
    assert cleaned == "The result is that the page is boxed. Chrome was not blocking fingerprinting in that year, while others did."
    english = retriever.Passage("x#1", "X", "A whole sentence about the protocol here. Another one.", "kb", language="en")
    assert fallback._usable_kb(english, "ro") is None
    assert fallback._usable_kb(english, "en")


@pytest.mark.parametrize("lang,name,question", CASES + [("ro", None, "Ce este UPNP?"), ("en", None, "HTTP")])
def test_fallback_never_calls_the_llm_and_never_changes_the_analysis(monkeypatch, offline, lang, name, question):
    monkeypatch.setattr("netcheck.learn.agent.ask", lambda *a, **k: pytest.fail("LLM was called"))
    analysis = attach_explanations(analyze_file(VALIDATION / "V4_legacy.xml"), lang)
    before = deepcopy(analysis)
    for device_ip in (None, "192.168.1.1"):
        text, sources = fallback.answer(question, analysis, lang=lang, device_ip=device_ip)
        assert text and sources
        assert text == fallback.answer(question, analysis, lang=lang, device_ip=device_ip)[0]
    assert analysis == before


def test_asking_does_not_change_the_saved_scan(monkeypatch, tmp_path, offline):
    client, scan_id, _ = _client(monkeypatch, tmp_path)
    before = history.get_scan(scan_id)
    for lang, _, question in CASES:
        _ask(client, scan_id, question, lang, "192.168.1.1")
    assert history.get_scan(scan_id) == before
