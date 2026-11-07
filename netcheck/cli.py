"""Local CLI: configure-lab, network, scan, demo-refusals and serve."""
import argparse
from dataclasses import asdict
import json
from pathlib import Path
import subprocess
import sys
from unittest.mock import patch

from netcheck import scanner, service


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
                    target, [safe_network], confirm=confirm,
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


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="netcheck")
    parser.add_argument("--config", type=Path, default=scanner._DEFAULT_LAB_CONFIG)
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("network", help="Detect IPv4 network without scanning")
    configure = commands.add_parser("configure-lab", help="Authorize the connected lab after confirmation")
    configure.add_argument("--allow", action="append")
    configure.add_argument("--confirm", action="store_true")
    commands.add_parser("demo-refusals", help="Demonstrate authorization refusals without Nmap")
    scan = commands.add_parser("scan")
    scan.add_argument("target")
    scan.add_argument("--confirm", action="store_true")
    scan.add_argument("--output-dir", type=Path, default=None)
    serve = commands.add_parser("serve", help="Serve local API on 127.0.0.1")
    serve.add_argument("--port", type=int, default=8000)
    serve.add_argument("--output-dir", type=Path, default=None)
    args = parser.parse_args(argv)
    try:
        if args.command == "network":
            result = asdict(scanner.detect_network())
        elif args.command == "configure-lab":
            allowed = args.allow
            if allowed is None:
                proposal = scanner.detect_network()
                print(
                    "Propunere subnet detectat / Detected subnet proposal: "
                    f"{proposal.subnet}"
                )
                allowed = [proposal.subnet]
            scanner.configure_lab_network(allowed, confirm=args.confirm, config_path=args.config)
            result = {"configured": True, "config": str(args.config)}
        elif args.command == "demo-refusals":
            return _demo_refusals()
        elif args.command == "scan":
            outcome = service.scan(args.target, confirm=args.confirm,
                                   config_path=args.config, output_dir=args.output_dir)
            print(json.dumps(asdict(outcome), ensure_ascii=False))
            return 0 if outcome.success else 1
        else:
            import uvicorn
            from netcheck.api import create_app
            uvicorn.run(create_app(config_path=args.config, output_dir=args.output_dir),
                        host="127.0.0.1", port=args.port)
            return 0
        print(json.dumps(result, ensure_ascii=False))
        return 0
    except (PermissionError, scanner.NetworkDetectionError, service.ScanBusyError) as exc:
        print(str(exc), file=sys.stderr)
        return 2
    except OSError as exc:
        print(f"Eroare de operare / Operation failed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
