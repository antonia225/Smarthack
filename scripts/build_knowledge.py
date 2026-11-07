"""Download allowlisted knowledge sources into short, attributed Markdown files."""

from __future__ import annotations

from datetime import datetime, timezone
import json
from pathlib import Path
import re
import sys
from urllib.request import Request, urlopen

ROOT = Path(__file__).resolve().parents[1]
SOURCES = ROOT / "knowledge" / "sources.json"
OUTPUT = ROOT / "knowledge"
MAX_BYTES = 2_000_000
MAX_PASSAGE_CHARS = 1_200


def _plain_text(raw: bytes) -> str:
    html = raw.decode("utf-8", errors="replace")
    html = re.sub(r"<script\b[^>]*>.*?</script>", " ", html, flags=re.I | re.S)
    html = re.sub(r"<style\b[^>]*>.*?</style>", " ", html, flags=re.I | re.S)
    text = re.sub(r"<[^>]+>", " ", html)
    return re.sub(r"\s+", " ", text).strip()


def build_source(source: dict[str, object]) -> Path:
    source_id = str(source["id"])
    request = Request(
        str(source["url"]),
        headers={"User-Agent": "NetCheck knowledge builder/1.0"},
    )
    with urlopen(request, timeout=15) as response:
        content = response.read(MAX_BYTES + 1)
    if len(content) > MAX_BYTES:
        raise ValueError(f"{source_id}: response exceeds {MAX_BYTES} bytes")
    passage = _plain_text(content)[:MAX_PASSAGE_CHARS].strip()
    if not passage:
        raise ValueError(f"{source_id}: empty response")
    retrieved = datetime.now(timezone.utc).isoformat()
    output = (
        f"---\nsource_url: {source['url']}\nlicense: {source['license']}\n"
        f"attribution: {source['attribution']}\nretrieved: {retrieved}\n---\n\n"
        f"{passage}\n"
    )
    destination = OUTPUT / f"{source_id}.md"
    destination.write_text(output, encoding="utf-8")
    return destination


def main() -> int:
    sources = json.loads(SOURCES.read_text(encoding="utf-8"))
    failures = 0
    for source in sources:
        try:
            print(f"Downloading {source['id']}…")
            print(build_source(source))
        except (OSError, ValueError) as exc:
            failures += 1
            print(f"Could not retrieve {source['id']}: {exc}", file=sys.stderr)
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
