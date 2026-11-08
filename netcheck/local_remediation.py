"""Finding-scoped remediation for the explicitly configured Docker lab."""

from __future__ import annotations

import subprocess
from pathlib import Path
from typing import Iterable

from . import scanner


_SERVICES_BY_FINDING = {
    "TELNET_OPEN": ("simulators",),
    "FTP_CLEARTEXT": ("simulators",),
    "MQTT_EXPOSED": ("mqtt",),
    "DB_EXPOSED": ("db",),
    "HTTP_ADMIN_CLEARTEXT": ("simulators",),
}


class LocalRemediationError(RuntimeError):
    """The lab cannot safely apply the requested remediation."""


def _services(finding_code: str) -> tuple[str, ...]:
    try:
        return _SERVICES_BY_FINDING[finding_code]
    except KeyError as exc:
        raise LocalRemediationError(
            f"No safe local remediation exists for {finding_code}"
        ) from exc


def apply(
    *,
    device_ip: str,
    finding_code: str,
    services_dir: str | Path | None = None,
    runner=None,
) -> None:
    """Stop only allowlisted lab services for a private, configured target."""

    try:
        validated = scanner.validate_scan_request(device_ip, confirm=True)
    except (PermissionError, ValueError, OSError) as exc:
        raise LocalRemediationError("Target is not in the configured lab") from exc
    lab_host_ip = getattr(getattr(validated, "network", None), "ip", None)
    if lab_host_ip and device_ip != lab_host_ip:
        raise LocalRemediationError(
            "The selected device is not the local Docker lab host"
        )

    services = _services(finding_code)
    directory = Path(services_dir or Path(__file__).resolve().parent.parent / "lab" / "services")
    if not directory.is_dir():
        raise LocalRemediationError("Lab services directory is unavailable")
    if runner is None:
        runner = subprocess.run
    try:
        runner(
            ["docker", "compose", "stop", *services],
            cwd=directory,
            check=True,
            capture_output=True,
            text=True,
            timeout=30,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise LocalRemediationError("The lab service could not be stopped") from exc


def supported_findings() -> Iterable[str]:
    """Return finding codes with a safe local lab action."""

    return _SERVICES_BY_FINDING
