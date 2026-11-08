"""Explicit, finding-scoped requests to a configured remediation agent."""
from __future__ import annotations

import json
import os
from typing import Literal
from urllib.request import Request, urlopen
from urllib.parse import urlparse

from fastapi import APIRouter, HTTPException, Request as FastAPIRequest
from pydantic import BaseModel, ConfigDict, StrictBool, StrictStr
from netcheck import auth, history
from netcheck.catalog import attach_explanations
from netcheck.local_remediation import LocalRemediationError, apply as apply_local

router = APIRouter()


class RemediationRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    scan_id: int
    device_ip: StrictStr
    finding_code: StrictStr
    port: int | None = None
    lang: Literal["ro", "en"] = "ro"
    confirm: StrictBool = False


def _finding(scan_id: int, device_ip: str, finding_code: str, port: int | None, lang: str, user_id: int | None = None) -> dict:
    try:
        scan = history.get_scan(scan_id, user_id=user_id)
    except KeyError as exc:
        raise HTTPException(404, detail="scan_not_found") from exc
    if scan.get("status") != "ok":
        raise HTTPException(404, detail="scan_not_found")
    decorated = attach_explanations(scan, lang)
    for finding in decorated.get("findings", []):
        if (
            finding.get("ip") == device_ip
            and finding.get("code") == finding_code
            and finding.get("port") == port
        ):
            return finding
    raise HTTPException(404, detail="finding_not_found")


@router.post("/api/agent/plan")
def plan(request: RemediationRequest, http_request: FastAPIRequest):
    user = auth.get_session(http_request.cookies.get(auth.SESSION_COOKIE))
    finding = _finding(
        request.scan_id,
        request.device_ip,
        request.finding_code,
        request.port,
        request.lang,
        user["id"] if user else None,
    )
    return {
        "status": "proposed",
        "finding": {
            "code": finding["code"],
            "title": finding["title"],
            "explain": finding["explain"],
            "fix": finding["fix"],
        },
        "requires_confirmation": True,
    }


@router.post("/api/agent/remediate")
def remediate(request: RemediationRequest, http_request: FastAPIRequest):
    user = auth.get_session(http_request.cookies.get(auth.SESSION_COOKIE))
    if not request.confirm:
        raise HTTPException(400, detail="confirmation_required")
    _finding(
        request.scan_id,
        request.device_ip,
        request.finding_code,
        request.port,
        request.lang,
        user["id"] if user else None,
    )
    endpoint = os.environ.get("NETCHECK_REMEDIATION_URL", "")
    payload = request.model_dump(exclude={"confirm"})
    if endpoint == "local://lab":
        try:
            apply_local(
                device_ip=request.device_ip,
                finding_code=request.finding_code,
            )
        except LocalRemediationError as exc:
            raise HTTPException(503, detail="agent_failed") from exc
        return {"status": "ok"}
    parsed = urlparse(endpoint)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise HTTPException(503, detail="agent_unavailable")
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
