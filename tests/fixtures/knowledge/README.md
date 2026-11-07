# Knowledge fixtures

`retrieval-index.json` contains only the first downloaded passage of each of
ten Wikipedia documents, without generated explanatory text. Each document
retains its attribution, CC-BY-SA 4.0 license, revision ID, timestamp and source
URL. Trimming to one passage per document is the fixture transformation.
`retrieval-sources.json` is the corresponding allowlist subset.

`mdn-http.html` wraps an actual downloaded MDN passage in minimal test HTML;
only the fixture heading/navigation/markup are test scaffolding. Its text is
from https://developer.mozilla.org/en-US/docs/Web/HTTP/Overview, attributed to
MDN Web Docs contributors, CC-BY-SA 2.5 or later. The corresponding version is
recorded in knowledge/mdn-http.md and docs/NOTICE.md.

These are frozen offline test inputs. Tests do not download or fabricate
encyclopedia explanations, and do not prove the full corpus is available.
