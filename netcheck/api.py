"""Local FastAPI application for NetCheck history and live scans."""

from __future__ import annotations

from dataclasses import asdict
from pathlib import Path
import tempfile
from typing import Any, Literal

from fastapi import FastAPI, HTTPException, Query, Request
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, ConfigDict, StrictBool, StrictStr
from starlette.middleware.trustedhost import TrustedHostMiddleware

from netcheck import history, scanner, service
from netcheck.scoring import analyze_file
from netcheck.catalog import CatalogError, attach_explanations
from netcheck.learn_api import router as learn_router
from netcheck.report import render_report


class ScanRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    target: StrictStr
    confirm: StrictBool = False


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
    application.include_router(learn_router)

    @application.get("/api/report", response_class=HTMLResponse)
    def report(
        a: int = Query(...),
        b: int | None = Query(None),
        lang: Literal["ro", "en"] = Query("ro"),
    ) -> HTMLResponse:
        try:
            current = history.get_scan(b if b is not None else a)
            before = history.get_scan(a) if b is not None else None
        except KeyError as exc:
            raise HTTPException(status_code=404, detail="Scan not found.") from exc
        if current.get("status") != "ok" or (before is not None and before.get("status") != "ok"):
            raise HTTPException(status_code=400, detail="Reports need valid scans.")
        return HTMLResponse(render_report(current, before=before, lang=lang))

    @application.exception_handler(CatalogError)
    async def catalog_error(request: Request, exc: CatalogError) -> JSONResponse:
        return _error_response(
            "catalog_unavailable",
            "Catalogul de explicații lipsește sau este invalid. Restaurează catalog.json.",
            "The explanation catalog is missing or invalid. Restore catalog.json.",
            503,
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
        lang: Literal["ro", "en"] | None = Query(None),
    ) -> dict[str, Any]:
        content = await request.body()
        # The client name is display metadata, never a filesystem path. Handle
        # both path separators regardless of the server's operating system.
        display_name = filename.replace("\\", "/").rsplit("/", 1)[-1] or "scan.xml"
        with tempfile.TemporaryDirectory(prefix="netcheck-import-") as directory:
            path = Path(directory) / "scan.xml"
            path.write_bytes(content)
            analysis = analyze_file(path)
        analysis["file"] = display_name
        explained = attach_explanations(analysis, lang)
        scan_id = history.save_scan(analysis)
        return {"scan_id": scan_id, **explained}

    @application.get("/api/scans")
    def scans() -> list[dict[str, Any]]:
        return history.list_scans()

    @application.get("/api/scans/{scan_id}")
    def scan(
        scan_id: int, lang: Literal["ro", "en"] | None = Query(None),
    ) -> dict[str, Any]:
        try:
            analysis = history.get_scan(scan_id)
        except KeyError as exc:
            raise HTTPException(status_code=404, detail="Scan not found.") from exc

        return attach_explanations(analysis, lang)

    @application.get("/api/scans/{scan_id}/answers")
    def answers(scan_id: int) -> list[dict[str, Any]]:
        try:
            history.get_scan(scan_id)
        except KeyError as exc:
            raise HTTPException(status_code=404, detail="Scan not found.") from exc
        return history.list_answers(scan_id)

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
    def live_scan(
        request: ScanRequest, lang: Literal["ro", "en"] | None = Query(None),
    ) -> dict[str, Any] | JSONResponse:
        try:
            result = service.scan(
                request.target,
                confirm=request.confirm,
                config_path=config_path,
                output_dir=output_dir,
            )
            if not result.success:
                return _error_response(
                    "scan_failed",
                    result.error or "Scanarea a eșuat.",
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

        explained = attach_explanations(analysis, lang)
        scan_id = history.save_scan(analysis)
        return {"scan_id": scan_id, **asdict(result), **explained}

    web_directory = Path(__file__).with_name("web")
    if web_directory.is_dir():
        application.mount(
            "/",
            StaticFiles(directory=web_directory, html=True),
            name="web",
        )
    return application


app = create_app()
