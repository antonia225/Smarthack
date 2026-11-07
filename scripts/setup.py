"""Create the project virtual environment and install development requirements."""

from __future__ import annotations

import os
from pathlib import Path
import shutil
import subprocess
import sys
import venv


ROOT = Path(__file__).resolve().parents[1]
VENV = ROOT / ".venv"
REQUIREMENTS = ROOT / "requirements-dev.txt"


def venv_python() -> Path:
    if os.name == "nt":
        return VENV / "Scripts" / "python.exe"
    return VENV / "bin" / "python"


def main() -> int:
    if venv_python().exists():
        print("Using existing virtual environment / Se folosește mediul virtual existent...")
    else:
        print("Creating virtual environment / Se creează mediul virtual...")
        venv.EnvBuilder(with_pip=True).create(VENV)
    interpreter = venv_python()
    subprocess.run(
        [str(interpreter), "-m", "pip", "install", "-r", str(REQUIREMENTS)],
        check=True,
    )

    nmap = shutil.which("nmap")
    if nmap:
        print(f"Nmap found / Nmap găsit: {nmap}")
    else:
        print(
            "Nmap missing / Nmap lipsește: install it separately before live scanning "
            "/ instalați-l separat înainte de scanarea live."
        )
    print(
        "Setup complete / Instalare finalizată. "
        f"Use {interpreter} to run Netcheck and tests."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
