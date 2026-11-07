"""Local FastAPI application for NetCheck history and live scans."""

from __future__ import annotations

from pathlib import Path
import tempfile
from typing import Any

from fastapi import FastAPI, Query, Request
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from . import history
from .scanner import run_scan, validate_scan_request
from .scoring import analyze_file


app = FastAPI(title="NetCheck")


class ScanRequest(BaseModel):
    target: str
    allowed_networks: list[str] | None = None
    confirm: bool = False


def _error_response(
    code: str,
    message_ro: str,
    message_en: str,
    status_code: int,
) -> JSONResponse:
    return JSONResponse(
        status_code=status_code,
        content={
            "status": "error",
            "error": {
                "code": code,
                "message": {"ro": message_ro, "en": message_en},
            },
        },
    )


@app.post("/api/import")
async def import_scan(request: Request, filename: str = Query("scan.xml")) -> dict[str, Any]:
    """Import one XML document from the request body and save its analysis."""

    content = await request.body()
    safe_name = Path(filename).name or "scan.xml"
    with tempfile.TemporaryDirectory(prefix="netcheck-import-") as directory:
        path = Path(directory) / safe_name
        path.write_bytes(content)
        analysis = analyze_file(path)

    scan_id = history.save_scan(analysis)
    return {"scan_id": scan_id, **analysis}


@app.get("/api/scans")
def scans() -> list[dict[str, Any]]:
    return history.list_scans()


@app.get("/api/scans/{scan_id}")
def scan(scan_id: int) -> dict[str, Any]:
    try:
        return history.get_scan(scan_id)
    except KeyError as exc:
        raise _not_found("Scan not found.") from exc


@app.get("/api/compare")
def compare_scans(
    a: int = Query(...),
    b: int = Query(...),
) -> dict[str, Any]:
    try:
        return history.compare(a, b)
    except KeyError as exc:
        raise _not_found("Scan not found.") from exc
    except ValueError as exc:
        raise _bad_request(str(exc)) from exc


@app.delete("/api/history")
def clear_history() -> dict[str, str]:
    history.delete_history()
    return {"status": "ok"}


@app.post("/api/scan", response_model=None)
def live_scan(request: ScanRequest) -> dict[str, Any] | JSONResponse:
    """Validate and run one authorized live scan without elevating the API."""

    try:
        validated = validate_scan_request(
            request.target,
            request.allowed_networks,
            request.confirm,
        )
    except PermissionError as exc:
        return _error_response(
            "permission_denied",
            str(exc),
            str(exc),
            403,
        )

    with tempfile.TemporaryDirectory(prefix="netcheck-scan-") as directory:
        output_path = str(Path(directory) / "scan.xml")
        result = run_scan(validated, output_path)
        if not result.success:
            return _error_response(
                "scan_failed",
                result.error or "Scanarea a eșuată.",
                result.error or "The scan failed.",
                502,
            )

        analysis = analyze_file(output_path)
    scan_id = history.save_scan(analysis)
    return {"scan_id": scan_id, **analysis}


def _not_found(message: str) -> Exception:
    from fastapi import HTTPException

    return HTTPException(status_code=404, detail=message)


def _bad_request(message: str) -> Exception:
    from fastapi import HTTPException

    return HTTPException(status_code=400, detail=message)


web_directory = Path(__file__).with_name("web")
if web_directory.is_dir():
    app.mount("/", StaticFiles(directory=web_directory, html=True), name="web")
