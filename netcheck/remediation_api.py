"""Explicit, finding-scoped requests to a configured remediation agent."""
from __future__ import annotations

import json
import os
from typing import Literal
from urllib.request import Request, urlopen
from urllib.parse import urlparse

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, ConfigDict, StrictBool, StrictStr
from netcheck import history

router = APIRouter()


class RemediationRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    scan_id: int
    device_ip: StrictStr
    finding_code: StrictStr
    port: int | None = None
    lang: Literal["ro", "en"] = "ro"
    confirm: StrictBool = False


@router.post("/api/agent/remediate")
def remediate(request: RemediationRequest):
    if not request.confirm:
        raise HTTPException(400, detail="confirmation_required")
    try:
        scan = history.get_scan(request.scan_id)
    except KeyError as exc:
        raise HTTPException(404, detail="scan_not_found") from exc
    if scan.get("status") != "ok" or not any(
        f.get("ip") == request.device_ip and f.get("code") == request.finding_code
        and f.get("port") == request.port for f in scan.get("findings", [])
    ):
        raise HTTPException(404, detail="finding_not_found")
    endpoint = os.environ.get("NETCHECK_REMEDIATION_URL", "")
    parsed = urlparse(endpoint)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise HTTPException(503, detail="agent_unavailable")
    payload = request.model_dump(exclude={"confirm"})
    headers = {"Content-Type": "application/json"}
    key = os.environ.get("NETCHECK_REMEDIATION_API_KEY")
    if key:
        headers["Authorization"] = f"Bearer {key}"
    try:
        with urlopen(Request(endpoint, data=json.dumps(payload).encode(), headers=headers, method="POST"), timeout=8) as response:
            result = json.loads(response.read(65536))
        if not isinstance(result, dict) or result.get("status") not in {"ok", "accepted"}:
            raise ValueError("Agent did not accept the action")
    except (OSError, ValueError) as exc:
        raise HTTPException(502, detail="agent_failed") from exc
    return {"status": result["status"]}
