"""Local FastAPI application for NetCheck history and live scans."""

from __future__ import annotations

from dataclasses import asdict
from pathlib import Path
import tempfile
from typing import Any
from uuid import uuid4

from fastapi import FastAPI, HTTPException, Query, Request
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, ConfigDict, StrictBool, StrictStr
from starlette.middleware.trustedhost import TrustedHostMiddleware

from netcheck import history, scanner, service
from netcheck.scoring import analyze_file


run_scan = scanner.run_scan


class ScanRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    target: StrictStr
    confirm: StrictBool = False
    allowed_networks: list[str] | None = None


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


def _scan_output_path(output_dir: Path | None) -> tuple[Path, tempfile.TemporaryDirectory[str] | None]:
    if output_dir is not None:
        output_dir.mkdir(parents=True, exist_ok=True)
        return output_dir / f"api-scan-{uuid4().hex}.xml", None
    directory = tempfile.TemporaryDirectory(prefix="netcheck-scan-")
    return Path(directory.name) / "scan.xml", directory


def create_app(
    *,
    config_path: Path = scanner._DEFAULT_LAB_CONFIG,
    output_dir: Path | None = None,
) -> FastAPI:
    application = FastAPI(title="NetCheck")
    application.add_middleware(
        TrustedHostMiddleware,
        allowed_hosts=["127.0.0.1", "localhost", "[::1]", "testserver"],
    )

    @application.get("/api/network")
    def network() -> dict[str, Any]:
        try:
            return asdict(scanner.detect_network())
        except scanner.NetworkDetectionError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc

    @application.post("/api/import")
    async def import_scan(
        request: Request,
        filename: str = Query("scan.xml"),
    ) -> dict[str, Any]:
        content = await request.body()
        safe_name = Path(filename).name or "scan.xml"
        with tempfile.TemporaryDirectory(prefix="netcheck-import-") as directory:
            path = Path(directory) / safe_name
            path.write_bytes(content)
            analysis = analyze_file(path)
        scan_id = history.save_scan(analysis)
        return {"scan_id": scan_id, **analysis}

    @application.get("/api/scans")
    def scans() -> list[dict[str, Any]]:
        return history.list_scans()

    @application.get("/api/scans/{scan_id}")
    def scan(scan_id: int) -> dict[str, Any]:
        try:
            return history.get_scan(scan_id)
        except KeyError as exc:
            raise HTTPException(status_code=404, detail="Scan not found.") from exc

    @application.get("/api/compare")
    def compare_scans(
        a: int = Query(...),
        b: int = Query(...),
    ) -> dict[str, Any]:
        try:
            return history.compare(a, b)
        except KeyError as exc:
            raise HTTPException(status_code=404, detail="Scan not found.") from exc
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

    @application.delete("/api/history")
    def clear_history() -> dict[str, str]:
        history.delete_history()
        return {"status": "ok"}

    @application.post("/api/scan", response_model=None)
    def live_scan(request: ScanRequest) -> dict[str, Any] | JSONResponse:
        try:
            if request.allowed_networks is not None:
                validated = scanner.validate_scan_request(
                    request.target,
                    request.allowed_networks,
                    request.confirm,
                    config_path=config_path,
                )
                output_path, temporary_directory = _scan_output_path(output_dir)
                try:
                    result = run_scan(validated, str(output_path))
                    analysis_path = output_path
                    if not result.success:
                        return _error_response(
                            "scan_failed",
                            result.error or "Scanarea a eșuată.",
                            result.error or "The scan failed.",
                            502,
                        )
                    analysis = analyze_file(analysis_path)
                finally:
                    if temporary_directory is not None:
                        temporary_directory.cleanup()
            else:
                result = service.scan(
                    request.target,
                    confirm=request.confirm,
                    config_path=config_path,
                    output_dir=output_dir,
                )
                if not result.success:
                    return _error_response(
                        "scan_failed",
                        result.error or "Scanarea a eșuată.",
                        result.error or "The scan failed.",
                        502,
                    )
                analysis = analyze_file(result.xml_path)
        except service.ScanBusyError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc
        except PermissionError as exc:
            return _error_response(
                "permission_denied",
                str(exc),
                str(exc),
                403,
            )
        except scanner.NetworkDetectionError as exc:
            return _error_response(
                "network_detection_failed",
                str(exc),
                str(exc),
                409,
            )
        except OSError as exc:
            return _error_response(
                "operation_failed",
                "Eroare de operare.",
                "Operation failed.",
                500,
            )

        scan_id = history.save_scan(analysis)
        return {"scan_id": scan_id, **asdict(result), **analysis}

    web_directory = Path(__file__).with_name("web")
    if web_directory.is_dir():
        application.mount(
            "/",
            StaticFiles(directory=web_directory, html=True),
            name="web",
        )
    return application


app = create_app()
