"""Compare five laboratory service findings before and after remediation."""
from __future__ import annotations

import argparse
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
try:
    from lab.services.check_xml import EXPECTED, codes_for_paths
except ModuleNotFoundError as exc:
    if exc.name != "services":
        raise
    from services.check_xml import EXPECTED, codes_for_paths


def _xml_files(folder: Path) -> list[Path]:
    return sorted(folder.rglob("*.xml"))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Compare the five lab service checks; analyzer integration is pending."
    )
    parser.add_argument("before", type=Path)
    parser.add_argument("after", type=Path)
    args = parser.parse_args(argv)
    before_files = _xml_files(args.before)
    after_files = _xml_files(args.after)
    if not before_files or not after_files:
        print(
            "Lipsesc XML-uri BEFORE sau AFTER / BEFORE or AFTER XML files are missing",
            file=sys.stderr,
        )
        return 2
    before = codes_for_paths(before_files)
    after = codes_for_paths(after_files)
    resolved = sorted(before - after)
    introduced = sorted(after - before)
    print(f"BEFORE (cele cinci verificări / five checks): {sorted(before & EXPECTED)}")
    print(f"AFTER (cele cinci verificări / five checks): {sorted(after & EXPECTED)}")
    print(f"Rezolvate / Resolved: {resolved or 'niciuna / none'}")
    print(f"Noi / Introduced: {introduced or 'niciuna / none'}")
    print(
        "Scorul și pragul de minimum două findings sunt TODO până la implementarea "
        "analyzerului; nu se calculează manual. / Score and the two-finding threshold "
        "are TODO until the analyzer exists; they are not calculated manually."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
