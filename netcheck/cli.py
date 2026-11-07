"""Command-line entry points for NetCheck analysis."""

from __future__ import annotations

import argparse
import csv
from pathlib import Path

from .scoring import analyze_file, sort_findings_for_csv


def _analyze_command(folder: Path, output: Path) -> int:
    output.mkdir(parents=True, exist_ok=True)
    results = [analyze_file(path) for path in sorted(folder.glob("*.xml"))]

    with (output / "findings.csv").open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(
            handle,
            fieldnames=["file", "ip", "port", "finding_code", "severity"],
        )
        writer.writeheader()
        for finding in sort_findings_for_csv(results):
            writer.writerow(
                {
                    "file": finding["file"],
                    "ip": finding["ip"],
                    "port": "" if finding["port"] is None else finding["port"],
                    "finding_code": finding["code"],
                    "severity": finding["severity"],
                }
            )

    with (output / "scores.csv").open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=["file", "network_score"])
        writer.writeheader()
        for result in results:
            writer.writerow(
                {
                    "file": result["file"],
                    "network_score": (
                        result["network_score"]
                        if result["status"] == "ok"
                        else "ERROR"
                    ),
                }
            )
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="netcheck")
    commands = parser.add_subparsers(dest="command", required=True)

    analyze = commands.add_parser("analyze", help="Analyze Nmap XML files")
    analyze.add_argument("folder", type=Path)
    analyze.add_argument("--out", required=True, type=Path)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.command == "analyze":
        return _analyze_command(args.folder, args.out)
    parser.error(f"Unknown command: {args.command}")
    return 2
