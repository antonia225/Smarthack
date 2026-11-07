"""Local FastAPI application; lab authorization is configured outside HTTP."""
from dataclasses import asdict
from pathlib import Path

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, ConfigDict, StrictBool, StrictStr
from starlette.middleware.trustedhost import TrustedHostMiddleware

from netcheck import scanner, service


class ScanRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    target: StrictStr
    confirm: StrictBool = False


def create_app(*, config_path: Path = scanner._DEFAULT_LAB_CONFIG,
               output_dir: Path = Path("scans")) -> FastAPI:
    application = FastAPI(title="Netcheck local scanner")
    application.add_middleware(TrustedHostMiddleware, allowed_hosts=["127.0.0.1", "localhost", "[::1]"])

    @application.get("/api/network")
    def network():
        try:
            return asdict(scanner.detect_network())
        except scanner.NetworkDetectionError as exc:
            raise HTTPException(409, detail=str(exc)) from exc

    @application.post("/api/scan")
    def scan(request: ScanRequest):
        try:
            result = service.scan(request.target, confirm=request.confirm,
                                  config_path=config_path, output_dir=output_dir)
        except service.ScanBusyError as exc:
            raise HTTPException(409, detail=str(exc)) from exc
        except PermissionError as exc:
            raise HTTPException(403, detail=str(exc)) from exc
        except scanner.NetworkDetectionError as exc:
            raise HTTPException(409, detail=str(exc)) from exc
        except OSError as exc:
            raise HTTPException(500, detail="Eroare de operare / Operation failed") from exc
        if not result.success:
            raise HTTPException(502, detail=result.error)
        return asdict(result)

    return application


app = create_app()
