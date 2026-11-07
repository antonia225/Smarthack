"""Twenty bilingual top-3 checks against frozen, attributed source excerpts."""
import ast
import json
from pathlib import Path
import re
from urllib.parse import urlparse

import pytest

from netcheck.catalog import load_catalog
from netcheck.learn import retriever
from scripts import build_knowledge as builder

ROOT = Path(__file__).parents[1]
FIXTURES = Path(__file__).parent / 'fixtures' / 'knowledge'
QUESTIONS = [
    ('ro', 'Ce este Telnet și autentificare la distanță?', 'telnet'),
    ('ro', 'Cum funcționează desktop la distanță RDP?', 'rdp'),
    ('ro', 'Ce este o adresă IP?', 'ip-address'),
    ('ro', 'Ce este o subrețea și mască de rețea?', 'subnetwork'),
    ('ro', 'Ce face un paravan de protecție firewall?', 'firewall'),
    ('ro', 'Ce este transfer fișiere FTP?', 'ftp'),
    ('ro', 'Cum funcționează translatare adrese NAT?', 'nat'),
    ('ro', 'Cum funcționează partajare fișiere SMB?', 'smb'),
    ('ro', 'Ce face un broker mesaje MQTT?', 'mqtt'),
    ('ro', 'Cum funcționează rezolvare nume locale mDNS?', 'mdns'),
    ('en', 'What is Telnet remote login?', 'telnet'),
    ('en', 'How does Remote Desktop Protocol RDP work?', 'rdp'),
    ('en', 'What is an IP address?', 'ip-address'),
    ('en', 'What is a subnetwork and subnet mask?', 'subnetwork'),
    ('en', 'How does firewall packet filtering work?', 'firewall'),
    ('en', 'What is File Transfer Protocol FTP?', 'ftp'),
    ('en', 'What is network address translation NAT?', 'nat'),
    ('en', 'What is Server Message Block SMB file sharing?', 'smb'),
    ('en', 'What is an MQTT message broker?', 'mqtt'),
    ('en', 'How does multicast DNS mDNS resolve local names?', 'mdns'),
]


@pytest.fixture
def frozen_corpus(monkeypatch, tmp_path):
    for target, source in [('sources.json', 'retrieval-sources.json'), ('index.json', 'retrieval-index.json')]:
        (tmp_path / target).write_bytes((FIXTURES / source).read_bytes())
    monkeypatch.setattr(retriever, 'KNOWLEDGE', tmp_path)
    return tmp_path


@pytest.mark.parametrize('lang,question,expected', QUESTIONS)
def test_expected_source_in_top_three(frozen_corpus, lang, question, expected):
    results = retriever.search(question, lang=lang, limit=3)
    assert expected in [passage.document_id for passage in results]
    assert results == retriever.search(question, lang=lang, limit=3)


def test_diacritics_and_case_are_normalized(frozen_corpus):
    assert retriever.search('PARTAJARE FIȘIERE SMB') == retriever.search('partajare fisiere smb')
    assert retriever.search('BAZĂ DE DATE') == retriever.search('baza de date')


def test_both_catalog_languages_are_searchable(frozen_corpus):
    ro = retriever._catalog_passages('ro')
    en = retriever._catalog_passages('en')
    assert [p.search_text for p in ro] == [p.search_text for p in en]
    assert all(p.text != q.text for p, q in zip(ro, en))


def test_empty_query_and_nonpositive_limit(frozen_corpus):
    assert retriever.search(' ?! ') == []
    assert retriever.search('telnet', limit=0) == []
    assert retriever.search('telnet', limit=-1) == []


def test_unallowlisted_url_is_not_indexed(frozen_corpus):
    index_path = frozen_corpus / 'index.json'
    index = json.loads(index_path.read_text())
    index['passages'][0]['source_url'] = 'https://untrusted.example/source'
    index_path.write_text(json.dumps(index))
    assert index['passages'][0]['id'][3:] not in [p.id for p in retriever.passages()]


def test_every_rules_code_has_documentation_or_explicit_marker():
    # Inspect literals; never execute or modify the rules engine to build the corpus.
    tree = ast.parse((ROOT / 'netcheck' / 'rules.py').read_text())
    catalog_codes = set(load_catalog())
    rule_codes = {node.value for node in ast.walk(tree) if isinstance(node, ast.Constant) and isinstance(node.value, str) and re.fullmatch(r'[A-Z]+(?:_[A-Z0-9]+)+', node.value)}
    assert rule_codes == catalog_codes
    sources = json.loads((ROOT / 'knowledge' / 'sources.json').read_text())
    assert catalog_codes <= {code for source in sources for code in source['codes']}
    index = json.loads((ROOT / 'knowledge' / 'index.json').read_text())
    ids = {entry['id'] for entry in index['passages']}
    for code in rule_codes:
        coverage = index['codes'][code]
        assert coverage['source_ids']
        if coverage['passage_ids']:
            assert coverage['status'] == 'documented'
            assert set(coverage['passage_ids']) <= ids
            assert all(any(p['id'] == pid and code in p['codes'] for p in index['passages']) for pid in coverage['passage_ids'])
        else:
            assert coverage['status'] == 'fără documentație încă'


def test_all_source_and_index_urls_are_https():
    sources = json.loads((ROOT / 'knowledge' / 'sources.json').read_text())
    builder.validate_sources(sources)
    index = json.loads((ROOT / 'knowledge' / 'index.json').read_text())
    urls = [s['url'] for s in sources] + [p['source_url'] for p in index['passages']]
    urls += [d['fetched_url'] for d in index['documents'] if 'fetched_url' in d]
    assert all(urlparse(url).scheme == 'https' for url in urls)
    assert not any(re.search(r'cloudflare|professormesser|bitdefender', url, re.I) for url in urls)


def test_real_passages_have_required_metadata_and_word_bounds():
    index = json.loads((ROOT / 'knowledge' / 'index.json').read_text())
    required = {'id', 'source_url', 'license', 'attribution', 'revision', 'retrieved', 'codes', 'keywords_en', 'keywords_ro'}
    for doc in index['documents']:
        if doc['status'] != 'ok':
            continue
        metadata, chunks = builder.read_document(ROOT / 'knowledge' / f"{doc['id']}.md")
        assert required <= metadata.keys()
        assert chunks
        assert all(80 <= len(chunk['text'].split()) <= 200 for chunk in chunks)
        assert [chunk['id'] for chunk in chunks] == doc['passage_ids']
        assert all(chunk['id'] == f"kb:{doc['id']}#{number}" for number, chunk in enumerate(chunks, 1))


def test_numbered_citation_is_not_mistaken_for_an_invented_port():
    from netcheck.learn.validator import validate

    passage = retriever.Passage('telnet#9876', 'Telnet', 'Telnet is a protocol.', 'kb')
    assert validate('Telnet is a protocol. [kb:telnet#9876]', '', [passage])
    assert not validate('Use port 9876. [kb:telnet#9876]', '', [passage])
    assert not validate('Telnet is a protocol. [kb:telnet#9999]', '', [passage])
