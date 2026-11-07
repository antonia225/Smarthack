"""Offline tests for the allowlisted corpus tooling."""

import json
from pathlib import Path

from netcheck.catalog import load_catalog
from netcheck.learn.retriever import passages
from scripts import build_knowledge


def test_retriever_has_a_catalog_passage_for_every_finding():
    codes = set(load_catalog())
    retrieved = {passage.id for passage in passages("en") if passage.source_type == "catalog"}
    assert codes <= retrieved


def test_builder_writes_attributed_fixture(monkeypatch, tmp_path):
    source = json.loads(
        (Path(__file__).parents[1] / "knowledge" / "sources.json").read_text()
    )[0]

    class Response:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            return None

        def read(self, size):
            return (
                Path(__file__).parent / "fixtures" / "knowledge" / "mdn-http.html"
            ).read_bytes()

    monkeypatch.setattr(build_knowledge, "OUTPUT", tmp_path)
    monkeypatch.setattr(build_knowledge, "urlopen", lambda *args, **kwargs: Response())
    destination = build_knowledge.build_source(source)
    content = destination.read_text(encoding="utf-8")
    assert "source_url:" in content
    assert "license:" in content
    assert "HTTP is an application-layer protocol" in content
