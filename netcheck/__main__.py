"""Run NetCheck as a Python module."""

import sys

from .cli import main


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "serve":
        import uvicorn

        uvicorn.run("netcheck.api:app", host="127.0.0.1", port=8000)
    else:
        raise SystemExit(main())
