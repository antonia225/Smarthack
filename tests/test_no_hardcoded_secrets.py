import re
import subprocess
from pathlib import Path


SECRET = re.compile(
    r"(?i)(?:password|secret|token|api[_-]?key)\s*[:=]\s*['\"][^'\"${}]{8,}['\"]"
)
PRIVATE_KEY = re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")


def test_tracked_files_have_no_obvious_hardcoded_secrets():
    root = Path(__file__).parents[1]
    files = subprocess.check_output(
        ["git", "-C", str(root), "ls-files", "-z"], text=False
    ).decode().split("\0")
    findings = []
    for name in files:
        if not name or Path(name).suffix in {".xml", ".md"}:
            continue
        text = (root / name).read_text(encoding="utf-8", errors="ignore")
        if SECRET.search(text) or PRIVATE_KEY.search(text):
            findings.append(name)
    assert not findings, f"Possible hardcoded secret in: {findings}"
