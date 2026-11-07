"""Offline fixture tests for cached downloads, segmentation and failure reporting."""
import json
from pathlib import Path
from urllib.error import HTTPError, URLError

import pytest

from netcheck.catalog import load_catalog
from netcheck.learn.retriever import passages
from scripts import build_knowledge as builder

FIXTURES = Path(__file__).parent / 'fixtures' / 'knowledge'
SOURCES = Path(__file__).parents[1] / 'knowledge' / 'sources.json'


class Response:
    headers = {'ETag': '"fixture"'}

    def __init__(self, raw, url='https://developer.mozilla.org/en-US/docs/Web/HTTP/Overview'):
        self.raw, self.url = raw, url

    def __enter__(self):
        return self

    def __exit__(self, *args):
        pass

    def read(self, size):
        return self.raw[:size]

    def geturl(self):
        return self.url


def test_retriever_has_catalog_for_every_finding():
    assert set(load_catalog()) <= {p.id for p in passages('en') if p.source_type == 'catalog'}


def test_builder_downloads_once_and_preserves_attribution(monkeypatch, tmp_path):
    source = next(s for s in json.loads(SOURCES.read_text()) if s['id'] == 'mdn-http')
    calls = []
    raw = (FIXTURES / 'mdn-http.html').read_bytes()

    def download(request, **kwargs):
        calls.append(request)
        return Response(raw)

    monkeypatch.setattr(builder, 'OUTPUT', tmp_path)
    monkeypatch.setattr(builder.time, 'sleep', lambda _: None)
    monkeypatch.setattr(builder, 'urlopen', download)
    destination = builder.build_source(source)
    first = destination.read_bytes()
    builder.build_source(source)
    assert destination.read_bytes() == first
    assert len(calls) == 1
    assert 'NetCheck' in calls[0].get_header('User-agent')
    metadata, chunks = builder.read_document(destination)
    assert metadata['id'] == source['id']
    assert metadata['source_url'] == source['url']
    assert metadata['license'] == source['license']
    assert metadata['revision']['sha256']
    assert all(80 <= len(chunk['text'].split()) <= 200 for chunk in chunks)
    assert 'HTTP is a protocol' in chunks[0]['text']
    assert chunks[0]['id'] == 'kb:mdn-http#1'


@pytest.mark.parametrize('size', [80, 199, 200, 201, 279, 401, 1001])
def test_segmentation_does_not_pad_drop_or_duplicate_words(size):
    # Synthetic numbered tokens test partitioning only, not source content or retrieval.
    words = [str(index) for index in range(size)]
    chunks = builder.split_passages(' '.join(words))
    assert all(80 <= len(chunk.split()) <= 200 for chunk in chunks)
    assert ' '.join(chunks).split() == words


def test_short_document_has_explicit_failure():
    with pytest.raises(builder.SourceUnavailable, match='cannot make'):
        builder.split_passages('short source')


def test_missing_wikipedia_title_is_explicit(monkeypatch):
    source = json.loads(SOURCES.read_text())[0]
    raw = json.dumps({'query': {'pages': [{'title': 'Missing title', 'missing': True}]}}).encode()
    monkeypatch.setattr(builder.time, 'sleep', lambda _: None)
    monkeypatch.setattr(builder, 'urlopen', lambda *a, **k: Response(raw, source['url']))
    with pytest.raises(builder.SourceUnavailable, match='title does not exist'):
        builder._download(source)


def test_offline_build_continues_and_marks_missing_codes(monkeypatch, tmp_path, capsys):
    sources = json.loads(SOURCES.read_text())[:2]
    manifest = tmp_path / 'sources.json'
    manifest.write_text(json.dumps(sources))
    monkeypatch.setattr(builder, 'SOURCES', manifest)
    monkeypatch.setattr(builder, 'OUTPUT', tmp_path)
    monkeypatch.setattr(builder, 'NOTICE', tmp_path / 'NOTICE.md')
    monkeypatch.setattr(builder, 'urlopen', lambda *a, **k: pytest.fail('offline must not access network'))
    assert builder.main(['--offline']) == 1
    index = json.loads((tmp_path / 'index.json').read_text())
    assert len(index['documents']) == 2
    assert all(doc['status'] == 'unavailable' for doc in index['documents'])
    assert index['codes']['TELNET_OPEN']['status'] == 'fără documentație încă'
    assert 'offline: no matching cached download' in capsys.readouterr().err


def test_download_error_does_not_stop_later_sources(monkeypatch, tmp_path, capsys):
    sources = json.loads(SOURCES.read_text())[:2]
    manifest = tmp_path / 'sources.json'; manifest.write_text(json.dumps(sources))
    monkeypatch.setattr(builder, 'SOURCES', manifest)
    monkeypatch.setattr(builder, 'OUTPUT', tmp_path)
    monkeypatch.setattr(builder, 'NOTICE', tmp_path / 'NOTICE.md')
    monkeypatch.setattr(builder.time, 'sleep', lambda _: None)
    calls = []

    def fail(request, **kwargs):
        calls.append(request)
        raise URLError('no internet')

    monkeypatch.setattr(builder, 'urlopen', fail)
    assert builder.main([]) == 1
    assert len(calls) == 2
    assert 'no internet' in capsys.readouterr().err


def test_rate_limit_has_no_automatic_retry(monkeypatch):
    source = json.loads(SOURCES.read_text())[0]
    calls = []
    monkeypatch.setattr(builder.time, 'sleep', lambda _: None)

    def limited(request, **kwargs):
        calls.append(request)
        raise HTTPError(source['url'], 429, 'Too Many Requests', {'Retry-After': '60'}, None)

    monkeypatch.setattr(builder, 'urlopen', limited)
    with pytest.raises(builder.SourceUnavailable, match='Retry-After=60; not retried'):
        builder._download(source)
    assert len(calls) == 1


def test_builder_extracts_main_without_navigation():
    raw = b'<body><nav>Menu</nav><main><header>Header</header><article><h1>HTTP</h1><p>Use &amp; understand TLS.</p><script>injection()</script></article></main><footer>Footer</footer></body>'
    assert builder._plain_text(raw) == 'HTTP Use & understand TLS.'


def test_offline_reuses_generated_markdown_without_cache(monkeypatch, tmp_path):
    source = next(s for s in json.loads(SOURCES.read_text()) if s['id'] == 'mdn-http')
    # Reuse the shipped, attributed document, as in a fresh checkout.
    original = SOURCES.parent / 'mdn-http.md'
    (tmp_path / 'mdn-http.md').write_bytes(original.read_bytes())
    monkeypatch.setattr(builder, 'OUTPUT', tmp_path)
    monkeypatch.setattr(builder, 'urlopen', lambda *a, **k: pytest.fail('must reuse Markdown offline'))
    result = builder.build_source(source, offline=True)
    metadata, chunks = builder.read_document(result)
    assert metadata['source_url'] == source['url']
    assert chunks


def test_redirects_cannot_copy_another_provider():
    from urllib.request import Request

    handler = builder.HTTPSOnly()
    request = Request('https://owasp.org/source')
    for url in ['http://owasp.org/source', 'https://www.cloudflare.com/source']:
        with pytest.raises(builder.SourceUnavailable):
            handler.redirect_request(request, None, 302, 'Found', {}, url)
