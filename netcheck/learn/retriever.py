"""Deterministic lexical BM25 over attributed passages and bilingual catalog text."""
from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
import json
from math import log
from pathlib import Path
import re
import unicodedata
from urllib.parse import urlparse

from netcheck.catalog import load_catalog

ROOT = Path(__file__).resolve().parents[2]
KNOWLEDGE = ROOT / 'knowledge'
TOKEN_RE = re.compile(r'[^\W_]+', re.UNICODE)
STOPWORDS = set('ce este sunt cum de la un o si sa pentru din care in pe cu the a an is are what how does do of to for and my can'.split())


@dataclass(frozen=True)
class Passage:
    id: str
    title: str
    text: str
    source_type: str
    url: str | None = None
    search_text: str = ''
    document_id: str = ''
    language: str = ''
    codes: tuple[str, ...] = ()


def _tokens(text: str) -> list[str]:
    normalized = ''.join(char for char in unicodedata.normalize('NFKD', text.casefold()) if not unicodedata.combining(char))
    return TOKEN_RE.findall(normalized)


def _knowledge_passages(lang: str = 'ro') -> list[Passage]:
    # Original source language is preserved. Both keyword languages are searchable.
    try:
        sources = json.loads((KNOWLEDGE / 'sources.json').read_text(encoding='utf-8'))
        allowed = {source['id']: source for source in sources}
        index = json.loads((KNOWLEDGE / 'index.json').read_text(encoding='utf-8'))
        if index.get('schema_version') != 2:
            return []
        successful = {doc['id'] for doc in index['documents'] if doc['status'] == 'ok'}
        result = []
        seen = set()
        for entry in sorted(index['passages'], key=lambda item: item['id']):
            doc_id = entry['document_id']
            source = allowed.get(doc_id)
            if not source or doc_id not in successful:
                continue
            if entry['source_url'] != source['url'] or urlparse(source['url']).scheme != 'https':
                continue
            if not re.fullmatch(r'kb:' + re.escape(doc_id) + r'#[1-9]\d*', entry['id']):
                continue
            if entry['id'] in seen or not 80 <= len(entry['text'].split()) <= 200:
                continue
            seen.add(entry['id'])
            keywords = ' '.join(source.get('keywords_en', []) + source.get('keywords_ro', []) + source.get('codes', []))
            result.append(Passage(entry['id'][3:], source['title'], entry['text'], 'kb', source['url'],
                                  f"{source['title']} {keywords} {entry['text']}", doc_id,
                                  str(source.get('language', '')), tuple(entry.get('codes', []))))
        return result
    except (OSError, ValueError, KeyError, TypeError):
        # A missing/invalid corpus never removes the local catalog fallback.
        return []


def _catalog_passages(lang: str) -> list[Passage]:
    result = []
    for code, entry in sorted(load_catalog().items()):
        def content(language):
            return f"{entry['title'][language]}. {entry['explain'][language]} {' '.join(entry['fix'][language])}"
        result.append(Passage(code, entry['title'][lang], content(lang), 'catalog',
                              search_text=f"{code} {content('ro')} {content('en')}", document_id=f'catalog:{code}',
                              language=lang, codes=(code,)))
    return result


def passages(lang: str = 'ro') -> list[Passage]:
    if lang not in {'ro', 'en'}:
        raise ValueError('lang must be ro or en')
    return _knowledge_passages(lang) + _catalog_passages(lang)


def search(question: str, *, lang: str = 'ro', limit: int = 4) -> list[Passage]:
    query = sorted(set(_tokens(question)) - STOPWORDS)
    if not query or limit <= 0:
        return []
    documents = passages(lang)
    counts = [Counter(_tokens(document.search_text or document.text)) for document in documents]
    lengths = [sum(count.values()) for count in counts]
    average = sum(lengths) / max(1, len(lengths))
    frequency = Counter(token for count in counts for token in count)
    scored = []
    for document, count, length in zip(documents, counts, lengths):
        score = 0.0
        for token in query:
            term_frequency = count[token]
            if term_frequency:
                idf = log(1 + (len(documents) - frequency[token] + 0.5) / (frequency[token] + 0.5))
                score += idf * term_frequency * 2.5 / (term_frequency + 1.5 * (0.25 + 0.75 * length / max(1, average)))
        if score:
            scored.append((score, document))
    scored.sort(key=lambda item: (-item[0], item[1].source_type, item[1].id))
    # Return the best passage per document so one long article cannot fill top 3.
    result, seen = [], set()
    for _, document in scored:
        key = document.document_id or f'{document.source_type}:{document.id}'
        if key in seen:
            continue
        seen.add(key)
        result.append(document)
        if len(result) == limit:
            break
    return result


def source_dict(passage: Passage) -> dict[str, str | None]:
    result = {'type': passage.source_type, 'id': passage.id, 'title': passage.title}
    if passage.url:
        result['url'] = passage.url
    return result
