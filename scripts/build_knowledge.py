"""Build attributed, cached Learning Mode passages using only the standard library."""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
from html.parser import HTMLParser
import json
from pathlib import Path
import re
import sys
import time
from urllib.error import HTTPError
from urllib.parse import urlencode, urlparse
from urllib.request import HTTPRedirectHandler, Request, build_opener

ROOT = Path(__file__).resolve().parents[1]
SOURCES = ROOT / 'knowledge' / 'sources.json'
OUTPUT = ROOT / 'knowledge'
NOTICE = ROOT / 'docs' / 'NOTICE.md'
MAX_BYTES = 8_000_000
USER_AGENT = 'NetCheck-LearningMode/2.0 (educational knowledge corpus builder; Python urllib)'


class SourceUnavailable(ValueError):
    """A source cannot provide usable, attributable text."""


class HTTPSOnly(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if urlparse(newurl).scheme != 'https':
            raise SourceUnavailable('non-HTTPS redirect refused')
        if urlparse(newurl).hostname.removeprefix('www.') != urlparse(req.full_url).hostname.removeprefix('www.'):
            raise SourceUnavailable('cross-host redirect refused; update the explicit source allowlist')
        return super().redirect_request(req, fp, code, msg, headers, newurl)


# A named seam for fixture tests; no retry, proxy bypass, or secondary scrape.
urlopen = build_opener(HTTPSOnly()).open


class _ContentParser(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.stack: list[tuple[str, bool]] = []
        self.parts = {key: [] for key in ('main', 'article', 'pre', 'body')}

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        hidden = tag in {'script', 'style', 'nav', 'header', 'footer', 'aside', 'sup'} or attrs.get('aria-hidden') == 'true'
        if tag not in {'area', 'base', 'br', 'col', 'embed', 'hr', 'img', 'input', 'link', 'meta', 'param', 'source', 'track', 'wbr'}:
            self.stack.append((tag, hidden))

    def handle_endtag(self, tag):
        for index in range(len(self.stack) - 1, -1, -1):
            if self.stack[index][0] == tag:
                self.stack = self.stack[:index]
                break

    def handle_data(self, data):
        if any(hidden for _, hidden in self.stack):
            return
        tags = {tag for tag, _ in self.stack}
        for tag, parts in self.parts.items():
            if tag in tags:
                parts.append(data)


def _plain_text(raw: bytes) -> str:
    parser = _ContentParser()
    parser.feed(raw.decode('utf-8', errors='replace'))
    for tag in ('main', 'article', 'pre', 'body'):
        text = re.sub(r'\s+', ' ', ' '.join(parser.parts[tag])).strip()
        if text:
            return text
    return ''


def validate_sources(sources):
    if not isinstance(sources, list):
        raise ValueError('sources.json must be an array')
    ids = set()
    for source in sources:
        source_id = source['id']
        if not re.fullmatch(r'[a-z0-9]+(?:-[a-z0-9]+)*', source_id) or source_id in ids:
            raise ValueError(f'invalid or duplicate source ID: {source_id}')
        ids.add(source_id)
        parsed = urlparse(source['url'])
        if parsed.scheme != 'https' or not parsed.hostname or parsed.username or parsed.password:
            raise ValueError(f'{source_id}: source URL must be HTTPS without credentials')
        if parsed.hostname not in {'en.wikipedia.org', 'developer.mozilla.org', 'www.cisa.gov', 'csrc.nist.gov', 'owasp.org', 'www.rfc-editor.org'}:
            raise ValueError(f'{source_id}: unsupported source host')
        for key in ('codes', 'keywords_en', 'keywords_ro'):
            if not isinstance(source[key], list) or any(not isinstance(value, str) or not value.strip() for value in source[key]):
                raise ValueError(f'{source_id}: invalid {key}')
        for key in ('license', 'attribution', 'title'):
            if not isinstance(source[key], str) or not source[key].strip():
                raise ValueError(f'{source_id}: missing {key}')
        if source.get('kind') not in {'html', 'wikipedia'}:
            raise ValueError(f'{source_id}: invalid source kind')
        if source['kind'] == 'wikipedia' and parsed.hostname != 'en.wikipedia.org':
            raise ValueError(f'{source_id}: Wikipedia source must use en.wikipedia.org')


def _download(source):
    url = source['url']
    if source['kind'] == 'wikipedia':
        url = 'https://en.wikipedia.org/w/api.php?' + urlencode({
            'action': 'query', 'format': 'json', 'formatversion': 2,
            'prop': 'extracts|revisions', 'explaintext': 1, 'exsectionformat': 'plain',
            'rvprop': 'ids|timestamp', 'redirects': 1, 'titles': source['title'],
        })
    request = Request(url, headers={'User-Agent': USER_AGENT, 'Accept': 'application/json' if source['kind'] == 'wikipedia' else 'text/html'})
    # Successful documents are cached. Space actual network requests; never auto-retry 429.
    time.sleep(1)
    try:
        response = urlopen(request, timeout=15)
    except HTTPError as exc:
        if exc.code == 404:
            raise SourceUnavailable(f"HTTP 404: title/page does not exist: {source['title']}") from exc
        if exc.code == 429:
            raise SourceUnavailable(f"HTTP 429: rate limited; Retry-After={exc.headers.get('Retry-After', 'unspecified')}; not retried") from exc
        raise
    with response:
        raw = response.read(MAX_BYTES + 1)
        final_url = response.geturl()
        if urlparse(final_url).scheme != 'https':
            raise SourceUnavailable('non-HTTPS response refused')
        etag = response.headers.get('ETag')
        modified = response.headers.get('Last-Modified')
    if len(raw) > MAX_BYTES:
        raise SourceUnavailable(f'response exceeds {MAX_BYTES} bytes')
    digest = hashlib.sha256(raw).hexdigest()
    revision = {'sha256': digest, 'etag': etag, 'last_modified': modified}
    if source['kind'] == 'wikipedia':
        data = json.loads(raw)
        if data.get('error'):
            raise SourceUnavailable(f"Wikipedia API error: {data['error'].get('code', 'unknown')}")
        pages = data.get('query', {}).get('pages', [])
        if not pages or pages[0].get('missing') or pages[0].get('invalid'):
            raise SourceUnavailable(f"Wikipedia title does not exist: {source['title']}")
        page = pages[0]
        revisions = page.get('revisions', [])
        if not revisions or not page.get('extract'):
            raise SourceUnavailable(f"Wikipedia title has no extract/revision: {source['title']}")
        revision.update(id=revisions[0]['revid'], timestamp=revisions[0]['timestamp'], title=page['title'])
        text = page['extract']
    else:
        text = _plain_text(raw)
        if source.get('content_start'):
            position = text.find(source['content_start'])
            if position < 0:
                raise SourceUnavailable('expected content marker missing; review source page')
            text = text[position:]
        revision['version'] = source.get('revision_hint', 'HTTP representation; see hash/ETag/Last-Modified')
    return dict(source_url=source['url'], fetched_url=final_url, revision=revision,
                retrieved=datetime.now(timezone.utc).isoformat(), text=re.sub(r'\s+', ' ', text).strip())


def split_passages(text: str) -> list[str]:
    """Partition source words, without padding, duplication or invented text."""
    words = text.split()
    if len(words) < 80:
        raise SourceUnavailable(f'only {len(words)} words; cannot make an 80–200 word passage')
    count = (len(words) + 199) // 200
    base, extra = divmod(len(words), count)
    passages, start = [], 0
    for index in range(count):
        size = base + (index < extra)
        passages.append(' '.join(words[start:start + size]))
        start += size
    return passages


def read_document(path):
    content = path.read_text(encoding='utf-8')
    _, header, body = content.split('---\n', 2)
    metadata = {key: json.loads(value) for key, value in (line.split(': ', 1) for line in header.strip().splitlines())}
    chunks = re.findall(r'^## (kb:[a-z0-9-]+#\d+)\n\n(.*?)(?=^## kb:|\Z)', body, flags=re.M | re.S)
    return metadata, [{'id': passage_id, 'text': text.strip()} for passage_id, text in chunks]


def build_source(source: dict, *, refresh=False, offline=False) -> Path:
    source_id = source['id']
    cache = OUTPUT / '.cache' / f'{source_id}.json'
    cached = None
    if cache.exists() and not refresh:
        try:
            cached = json.loads(cache.read_text(encoding='utf-8'))
            if cached['source_url'] != source['url'] or cached['request_title'] != source['title']:
                cached = None
        except (OSError, ValueError, KeyError, TypeError):
            cached = None
    if cached is None and not refresh:
        # A checked-in generated Markdown document is also a reusable download.
        # This permits offline rebuilds in a fresh clone without private cache files.
        try:
            metadata, stored = read_document(OUTPUT / f'{source_id}.md')
            if (metadata['id'] == source_id and metadata['source_url'] == source['url']
                    and metadata['title'] == source['title'] and stored
                    and all(chunk['id'] == f'kb:{source_id}#{number}'
                            and 80 <= len(chunk['text'].split()) <= 200
                            for number, chunk in enumerate(stored, 1))):
                cached = {key: metadata[key] for key in ('source_url', 'revision', 'retrieved')}
                cached.update(text=' '.join(chunk['text'] for chunk in stored),
                              fetched_url=metadata.get('fetched_url', source['url']), request_title=source['title'])
        except (OSError, ValueError, KeyError, TypeError):
            pass
    if cached is None:
        if offline:
            raise SourceUnavailable('offline: no matching cached download')
        cached = _download(source)
        cached['request_title'] = source['title']
        # Validate before caching; truncated/empty/missing documents cannot masquerade as success.
        split_passages(cached['text'])
        cache.parent.mkdir(parents=True, exist_ok=True)
        cache.write_text(json.dumps(cached, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    chunks = split_passages(cached['text'])
    metadata = {key: source[key] for key in ('id', 'license', 'attribution', 'codes', 'keywords_en', 'keywords_ro')}
    metadata.update(source_url=cached['source_url'], fetched_url=cached['fetched_url'], revision=cached['revision'], retrieved=cached['retrieved'], title=source['title'], language=source.get('language', 'en'))
    header = '\n'.join(f'{key}: {json.dumps(value, ensure_ascii=False)}' for key, value in metadata.items())
    body = '\n\n'.join(f'## kb:{source_id}#{index}\n\n{text}' for index, text in enumerate(chunks, 1))
    destination = OUTPUT / f'{source_id}.md'
    destination.write_text(f'---\n{header}\n---\n\n{body}\n', encoding='utf-8')
    return destination


def build_index(sources, results):
    documents, passages = [], []
    for source, result in zip(sources, results):
        document = {**source, 'status': 'unavailable', 'passage_ids': []}
        if isinstance(result, Exception):
            document['error'] = str(result)
        else:
            metadata, chunks = read_document(result)
            document.update(metadata, status='ok', passage_ids=[chunk['id'] for chunk in chunks])
            for chunk in chunks:
                passages.append({**chunk, 'document_id': source['id'], 'title': source['title'], 'source_url': source['url'], 'codes': source['codes'], 'keywords_en': source['keywords_en'], 'keywords_ro': source['keywords_ro']})
        documents.append(document)
    # Importing the catalog only reads JSON, never changes the analysis engine.
    codes = json.loads((ROOT / 'netcheck' / 'catalog.json').read_text(encoding='utf-8'))
    coverage = {}
    for code in sorted(codes):
        ids = [p['id'] for p in passages if code in p['codes']]
        coverage[code] = {'status': 'documented' if ids else 'fără documentație încă', 'passage_ids': ids,
                          'source_ids': [s['id'] for s in sources if code in s['codes']]}
    index = {'schema_version': 2, 'documents': documents, 'passages': passages, 'codes': coverage,
             'keywords_ro_missing': [s['id'] for s in sources if not s['keywords_ro']]}
    (OUTPUT / 'index.json').write_text(json.dumps(index, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    return index


def write_notice(index):
    lines = ['# Learning Mode — surse, atribuiri și versiuni', '',
             'Generat de `python scripts/build_knowledge.py` din `knowledge/sources.json`.',
             'Textul pasajelor este extras din surse, fără traducere sau completare generată.',
             'Transformări: eliminare markup/navigare, normalizare spații, segmentare 80–200 cuvinte.',
             'Cuvintele-cheie RO/EN sunt metadate editoriale de căutare, nu citate din surse.', '',
             'Wikipedia: CC-BY-SA 4.0; atribuirea include contributorii și istoricul paginii.',
             'MDN: CC-BY-SA 2.5 sau versiune ulterioară, conform paginii de licențiere MDN.',
             'OWASP: licența declarată pe fiecare sursă; verificați termenii paginii pentru redistribuire.',
             'CISA/NIST: material guvernamental SUA; pot exista materiale terțe cu termeni proprii.',
             'RFC 1918 precede RFC 5378: se păstrează notificările originale; nu se presupune retroactiv licența modernă.',
             'Hash-ul unei reprezentări HTTP nu este un număr de versiune editorială.',
             'Cloudflare, Professor Messer și Bitdefender NU sunt descărcate sau copiate.', '',
             '| Document | Licență și atribuire | Revizie / preluare | Stare |', '| --- | --- | --- | --- |']
    for doc in index['documents']:
        revision = json.dumps(doc.get('revision', {}), ensure_ascii=False, sort_keys=True).replace('|', '\\|')
        status = 'ok' if doc['status'] == 'ok' else doc.get('error', 'unavailable').replace('|', '\\|')
        lines.append(f"| [{doc['id']}]({doc['url']}) | {doc['license']}; {doc['attribution']} | `{revision}`; {doc.get('retrieved', '—')} | {status} |")
    lines += ['', '## Coduri fără documentație încă', '']
    missing = [code for code, value in index['codes'].items() if value['status'] != 'documented']
    lines += [', '.join(missing) if missing else 'Niciunul.', '', '## keywords_ro de completat', '',
              ', '.join(index['keywords_ro_missing']) or 'Niciun câmp lipsă; sinonimele locale pot fi extinse în sources.json.', '']
    NOTICE.write_text('\n'.join(lines), encoding='utf-8')


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--offline', action='store_true', help='rebuild only from cached downloads; never access the network')
    parser.add_argument('--refresh', action='store_true', help='explicitly download each source again')
    args = parser.parse_args(argv)
    if args.offline and args.refresh:
        parser.error('--offline and --refresh are mutually exclusive')
    sources = json.loads(SOURCES.read_text(encoding='utf-8'))
    validate_sources(sources)
    OUTPUT.mkdir(parents=True, exist_ok=True)

    def build(source):
        try:
            return build_source(source, refresh=args.refresh, offline=args.offline)
        except (OSError, ValueError, KeyError, TypeError) as exc:
            return exc

    results = [build(source) for source in sources]
    index = build_index(sources, results)
    write_notice(index)
    failures = 0
    for source, result in zip(sources, results):
        if isinstance(result, Exception):
            failures += 1
            print(f"UNAVAILABLE {source['id']} ({source['title']}): {result}", file=sys.stderr)
        else:
            print(f"OK {source['id']}: {result}")
    print(f"{len(sources) - failures}/{len(sources)} documents; {len(index['passages'])} passages; {failures} unavailable")
    print('keywords_ro missing: ' + (', '.join(index['keywords_ro_missing']) or 'none'))
    return 1 if failures else 0


if __name__ == '__main__':
    raise SystemExit(main())
