"""Read installed Nmap frequencies; do not guess the top TCP ports."""
import math
import os
from pathlib import Path
import shutil

UDP_PORTS = (53, 123, 161, 1900, 5353)


def services_file() -> Path:
    executable = shutil.which("nmap")
    if not executable:
        raise FileNotFoundError("Nmap lipsește / Nmap is not installed")
    candidates = []
    if os.environ.get("NMAPDIR"):
        candidates.append(Path(os.environ["NMAPDIR"]))
    if os.name == "nt":
        if os.environ.get("APPDATA"):
            candidates.append(Path(os.environ["APPDATA"]) / "nmap")
    else:
        candidates.append(Path.home() / ".nmap")
    for binary in (Path(executable), Path(executable).resolve()):
        candidates.extend((binary.parent, binary.parent.parent / "share" / "nmap"))
    candidates.extend((Path("/usr/local/share/nmap"), Path("/usr/share/nmap")))
    for directory in candidates:
        path = directory / "nmap-services"
        if path.is_file():
            return path
    raise FileNotFoundError("Lipsește nmap-services / Cannot find Nmap's service database")


def port_specification(path: Path | None = None) -> str:
    """Include top 1,000 TCP ports (all ties at cutoff), plus the five UDP ports."""
    path = path or services_file()
    frequencies = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        fields = line.split()
        if len(fields) < 3 or line.lstrip().startswith("#") or not fields[1].endswith("/tcp"):
            continue
        port = int(fields[1].split("/")[0])
        frequency = float(fields[2])
        if not 0 <= port <= 65535 or not math.isfinite(frequency) or not 0 <= frequency <= 1:
            raise ValueError("Date nmap-services invalide / Invalid nmap-services data")
        frequencies[port] = frequency
    if len(frequencies) < 1000:
        raise ValueError("nmap-services trebuie să conțină minimum 1000 porturi TCP / Incomplete service database")
    cutoff = sorted(frequencies.values(), reverse=True)[999]
    ports = sorted(port for port, frequency in frequencies.items() if frequency >= cutoff)
    return "T:" + ",".join(map(str, ports)) + ",U:" + ",".join(map(str, UDP_PORTS))
