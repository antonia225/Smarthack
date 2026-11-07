"""Local CLI for analysis, guarded scans, lab runs, and the API server."""

from __future__ import annotations

import argparse
from dataclasses import asdict
from datetime import datetime, timezone
import csv
import json
from ipaddress import ip_network
import platform
from pathlib import Path
import sys
from unittest.mock import patch

from netcheck import scanner, service
from netcheck.scoring import analyze_file, sort_findings_for_csv


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


def _demo_refusals() -> int:
    safe_network = "172.20.10.0/28"
    cases = (
        ("IP public / Public IP", "8.8.8.8", True),
        ("Țintă Wi-Fi locație / Venue Wi-Fi target", "10.240.0.5", True),
        ("Subnet Wi-Fi locație / Venue Wi-Fi subnet", "10.240.0.0/16", True),
        ("Fără --confirm / Without --confirm", "172.20.10.3", False),
    )
    with patch("netcheck.scanner.subprocess.run") as process:
        for label, target, confirm in cases:
            try:
                scanner.validate_scan_request(
                    target, [safe_network], confirm=confirm
                )
            except PermissionError as exc:
                print(f"REFUZAT / REFUSED: {label} ({target}): {exc}")
            else:
                print(
                    "EROARE / ERROR: refuzul a lipsit / refusal missing: "
                    f"{label} ({target})"
                )
                return 1
        if process.called:
            print(
                "EROARE / ERROR: subprocess a fost apelat / subprocess was called",
                file=sys.stderr,
            )
            return 1
    print("Confirmare: subprocess nu a fost apelat / subprocess was not called")
    return 0


def _write_lab_metadata(
    xml_path: Path,
    *,
    targets: list[str],
    network: scanner.NetworkInfo,
    duration_seconds: float,
) -> None:
    metadata = {
        "date": datetime.now(timezone.utc).isoformat(),
        "scanner_laptop": platform.node() or "unknown",
        "targets": targets,
        "duration_seconds": duration_seconds,
        "address_count": sum(
            ip_network(target, strict=False).num_addresses for target in targets
        ),
        "network": asdict(network),
    }
    with xml_path.with_suffix(".json").open("x", encoding="utf-8") as handle:
        json.dump(metadata, handle, ensure_ascii=False, indent=2)


def _lab_run(args) -> int:
    output_dir = Path("lab") / args.label
    output_dir.mkdir(parents=True, exist_ok=True)
    network = scanner.detect_network()
    results = []
    for target in args.targets:
        outcome = service.scan(
            target,
            confirm=args.confirm,
            config_path=args.config,
            output_dir=output_dir,
        )
        if not outcome.success:
            print(
                outcome.error or "Scanare eșuată / Scan failed",
                file=sys.stderr,
            )
            return 1
        xml_path = Path(outcome.xml_path)
        _write_lab_metadata(
            xml_path,
            targets=[target],
            network=network,
            duration_seconds=outcome.duration_seconds,
        )
        results.append(
            {
                "xml_path": str(xml_path),
                "metadata_path": str(xml_path.with_suffix(".json")),
                "duration_seconds": outcome.duration_seconds,
            }
        )
    print(json.dumps({"label": args.label, "results": results}, ensure_ascii=False))
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="netcheck")
    parser.add_argument("--config", type=Path, default=scanner._DEFAULT_LAB_CONFIG)
    commands = parser.add_subparsers(dest="command", required=True)

    analyze = commands.add_parser("analyze", help="Analyze Nmap XML files")
    analyze.add_argument("folder", type=Path)
    analyze.add_argument("--out", required=True, type=Path)
    commands.add_parser("network", help="Detect IPv4 network without scanning")
    configure = commands.add_parser(
        "configure-lab",
        help="Authorize the connected lab after confirmation",
    )
    configure.add_argument("--allow", action="append")
    configure.add_argument("--confirm", action="store_true")
    commands.add_parser(
        "demo-refusals",
        help="Demonstrate authorization refusals without Nmap",
    )
    scan = commands.add_parser("scan")
    scan.add_argument("target", nargs="?")
    scan.add_argument("--confirm", action="store_true")
    scan.add_argument("--output-dir", type=Path, default=None)
    lab_run = commands.add_parser(
        "lab-run",
        help="Save a guarded BEFORE or AFTER laboratory scan and metadata",
    )
    lab_run.add_argument("--label", choices=("before", "after"), required=True)
    lab_run.add_argument("targets", nargs="+")
    lab_run.add_argument("--confirm", action="store_true")
    serve = commands.add_parser("serve", help="Serve local API on 127.0.0.1")
    serve.add_argument("--port", type=int, default=8000)
    serve.add_argument("--output-dir", type=Path, default=None)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        if args.command == "analyze":
            return _analyze_command(args.folder, args.out)
        if args.command == "network":
            print(json.dumps(asdict(scanner.detect_network()), ensure_ascii=False))
            return 0
        if args.command == "configure-lab":
            allowed = args.allow
            if allowed is None:
                proposal = scanner.detect_network()
                print(
                    "Propunere subnet detectat / Detected subnet proposal: "
                    f"{proposal.subnet}"
                )
                allowed = [proposal.subnet]
            scanner.configure_lab_network(
                allowed,
                confirm=args.confirm,
                config_path=args.config,
            )
            print(json.dumps({"configured": True, "config": str(args.config)}))
            return 0
        if args.command == "demo-refusals":
            return _demo_refusals()
        if args.command == "scan":
            target = (
                args.target
                if args.target is not None
                else scanner.default_scan_target(args.config)
            )
            outcome = service.scan(
                target,
                confirm=args.confirm,
                config_path=args.config,
                output_dir=args.output_dir,
            )
            print(json.dumps(asdict(outcome), ensure_ascii=False))
            return 0 if outcome.success else 1
        if args.command == "lab-run":
            return _lab_run(args)

        import uvicorn
        from netcheck.api import create_app

        uvicorn.run(
            create_app(config_path=args.config, output_dir=args.output_dir),
            host="127.0.0.1",
            port=args.port,
        )
        return 0
    except (
        PermissionError,
        scanner.NetworkDetectionError,
        service.ScanBusyError,
    ) as exc:
        print(str(exc), file=sys.stderr)
        return 2
    except OSError as exc:
        print(f"Eroare de operare / Operation failed: {exc}", file=sys.stderr)
        return 1
