"""Bounded, entity-safe integrity checks, separate from the findings parser."""
from pathlib import Path

from defusedxml import ElementTree

MAX_XML_BYTES = 10 * 1024 * 1024


def read_completed_scan(path: str | Path):
    with Path(path).open("rb") as handle:
        content = handle.read(MAX_XML_BYTES + 1)
    if len(content) > MAX_XML_BYTES:
        raise ValueError("XML depășește 10 MB / XML exceeds 10 MB")
    root = ElementTree.fromstring(content)
    finished = root.find("runstats/finished")
    if root.tag != "nmaprun" or finished is None or finished.get("exit") != "success":
        raise ValueError("Scanare incompletă / Incomplete scan")
    if any(host.get("timedout") == "true" for host in root.findall("host")):
        raise ValueError("O țintă a depășit timpul alocat / A host timed out")
    return root
