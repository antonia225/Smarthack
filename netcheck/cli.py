"""Local CLI: configure-lab, network, scan and serve."""
import argparse
from dataclasses import asdict
import json
from pathlib import Path
import sys

from netcheck import scanner, service


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="netcheck")
    parser.add_argument("--config", type=Path, default=scanner._DEFAULT_LAB_CONFIG)
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("network", help="Detect IPv4 network without scanning")
    configure = commands.add_parser("configure-lab", help="Explicitly authorize the connected lab")
    configure.add_argument("--allow", action="append", required=True)
    configure.add_argument("--confirm", action="store_true")
    scan = commands.add_parser("scan")
    scan.add_argument("target")
    scan.add_argument("--confirm", action="store_true")
    scan.add_argument("--output-dir", type=Path, default=Path("scans"))
    serve = commands.add_parser("serve", help="Serve local API on 127.0.0.1")
    serve.add_argument("--port", type=int, default=8000)
    serve.add_argument("--output-dir", type=Path, default=Path("scans"))
    args = parser.parse_args(argv)
    try:
        if args.command == "network":
            result = asdict(scanner.detect_network())
        elif args.command == "configure-lab":
            scanner.configure_lab_network(args.allow, confirm=args.confirm, config_path=args.config)
            result = {"configured": True, "config": str(args.config)}
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
