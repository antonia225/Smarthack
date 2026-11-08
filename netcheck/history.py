"""Persist and compare scan history in SQLite."""

from __future__ import annotations

from contextlib import contextmanager
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import sqlite3
from typing import Any


DB_PATH = Path(os.environ.get("NETCHECK_DB", "netcheck.db"))


def _database_path(path: str | Path | None) -> Path:
    return Path(path) if path is not None else DB_PATH


def _open_connection(path: str | Path | None = None) -> sqlite3.Connection:
    connection = sqlite3.connect(_database_path(path))
    connection.row_factory = sqlite3.Row
    connection.executescript(
        """
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            file TEXT NOT NULL,
            source TEXT NOT NULL,
            scanned_at TEXT NOT NULL,
            network_score INTEGER,
            status TEXT NOT NULL,
            error_json TEXT,
            top_risk_json TEXT
        );
        CREATE TABLE IF NOT EXISTS findings (
            scan_id INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
            ip TEXT NOT NULL,
            port INTEGER,
            code TEXT NOT NULL,
            severity TEXT NOT NULL,
            points INTEGER NOT NULL,
            evidence TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS devices (
            scan_id INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
            ip TEXT NOT NULL,
            mac_masked TEXT NOT NULL,
            vendor TEXT NOT NULL,
            hostname TEXT NOT NULL,
            device_type TEXT NOT NULL,
            PRIMARY KEY (scan_id, ip)
        );
        CREATE TABLE IF NOT EXISTS device_ports (
            scan_id INTEGER NOT NULL,
            ip TEXT NOT NULL,
            port INTEGER NOT NULL,
            protocol TEXT NOT NULL,
            service TEXT NOT NULL,
            product TEXT NOT NULL,
            version TEXT NOT NULL,
            FOREIGN KEY (scan_id, ip) REFERENCES devices(scan_id, ip)
                ON DELETE CASCADE
        );
        CREATE TABLE IF NOT EXISTS ai_answers (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
            question TEXT NOT NULL,
            answer TEXT NOT NULL,
            mode TEXT NOT NULL,
            created_at TEXT NOT NULL
        );
        """
    )
    connection.execute("PRAGMA foreign_keys = ON")
    return connection


@contextmanager
def _connect(path: str | Path | None = None):
    connection = _open_connection(path)
    try:
        with connection:
            yield connection
    finally:
        connection.close()


def save_scan(analysis: dict[str, Any], db_path: str | Path | None = None) -> int:
    """Save an analysis result and return its database identifier."""

    scanned_at = datetime.now(timezone.utc).isoformat()
    with _connect(db_path) as connection:
        cursor = connection.execute(
            """
            INSERT INTO scans
                (file, source, scanned_at, network_score, status, error_json,
                 top_risk_json)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                str(analysis["file"]),
                str(analysis.get("source", analysis["file"])),
                scanned_at,
                analysis.get("network_score"),
                str(analysis["status"]),
                json.dumps(analysis.get("error"), ensure_ascii=False),
                json.dumps(analysis.get("top_risk"), ensure_ascii=False),
            ),
        )
        scan_id = int(cursor.lastrowid)

        if analysis["status"] == "ok":
            for finding in analysis.get("findings", []):
                connection.execute(
                    """
                    INSERT INTO findings
                        (scan_id, ip, port, code, severity, points, evidence)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        scan_id,
                        finding["ip"],
                        finding["port"],
                        finding["code"],
                        finding["severity"],
                        finding["points"],
                        finding["evidence"],
                    ),
                )
            for device in analysis.get("devices", []):
                connection.execute(
                    """
                    INSERT INTO devices
                        (scan_id, ip, mac_masked, vendor, hostname, device_type)
                    VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    (
                        scan_id,
                        device["ip"],
                        device.get("mac_masked", ""),
                        device.get("vendor", ""),
                        device.get("hostname", ""),
                        device.get("device_type", "unknown"),
                    ),
                )
                for port in device.get("ports", []):
                    connection.execute(
                        """
                        INSERT INTO device_ports
                            (scan_id, ip, port, protocol, service, product, version)
                        VALUES (?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            scan_id,
                            device["ip"],
                            port["port"],
                            port.get("protocol", ""),
                            port.get("service", ""),
                            port.get("product", ""),
                            port.get("version", ""),
                        ),
                    )
    return scan_id


def list_scans(db_path: str | Path | None = None) -> list[dict[str, Any]]:
    """List saved scans in insertion order (the UI uses the last as newest)."""

    with _connect(db_path) as connection:
        rows = connection.execute(
            """
            SELECT id, file, source, network_score, scanned_at, status
            FROM scans
            ORDER BY id
            """
        ).fetchall()
    return [dict(row) for row in rows]


def save_answer(
    scan_id: int,
    question: str,
    answer: str,
    mode: str,
    db_path: str | Path | None = None,
) -> int:
    """Save an assistant answer linked to a scan and return its identifier."""

    created_at = datetime.now(timezone.utc).isoformat(timespec="seconds")
    with _connect(db_path) as connection:
        connection.execute("PRAGMA foreign_keys = ON")
        cursor = connection.execute(
            """
            INSERT INTO ai_answers
                (scan_id, question, answer, mode, created_at)
            VALUES (?, ?, ?, ?, ?)
            """,
            (scan_id, question, answer, mode, created_at),
        )
        return int(cursor.lastrowid)


def list_answers(
    scan_id: int,
    db_path: str | Path | None = None,
) -> list[dict[str, Any]]:
    """List assistant answers for a scan in insertion order."""

    with _connect(db_path) as connection:
        rows = connection.execute(
            """
            SELECT id, question, answer, mode, created_at
            FROM ai_answers
            WHERE scan_id = ?
            ORDER BY id
            """,
            (scan_id,),
        ).fetchall()
    return [dict(row) for row in rows]


def get_scan(scan_id: int, db_path: str | Path | None = None) -> dict[str, Any]:
    """Return one saved scan in the same shape as ``analyze_file``."""

    with _connect(db_path) as connection:
        scan = connection.execute(
            "SELECT * FROM scans WHERE id = ?", (scan_id,)
        ).fetchone()
        if scan is None:
            raise KeyError(f"Scan {scan_id} was not found.")

        result: dict[str, Any] = {
            "file": scan["file"],
            "source": scan["source"],
            "status": scan["status"],
        }
        if scan["status"] != "ok":
            result["error"] = json.loads(scan["error_json"] or "null")
            return result

        result.update(
            {
                "network_score": scan["network_score"],
                "top_risk": json.loads(scan["top_risk_json"] or "null"),
                "devices": [],
                "findings": [],
            }
        )
        devices = connection.execute(
            """
            SELECT ip, mac_masked, vendor, hostname, device_type
            FROM devices WHERE scan_id = ? ORDER BY ip
            """,
            (scan_id,),
        ).fetchall()
        for device in devices:
            ports = connection.execute(
                """
                SELECT port, protocol, service, product, version
                FROM device_ports
                WHERE scan_id = ? AND ip = ?
                ORDER BY protocol, port
                """,
                (scan_id, device["ip"]),
            ).fetchall()
            result["devices"].append(
                {
                    **dict(device),
                    "ports": [dict(port) for port in ports],
                }
            )

        findings = connection.execute(
            """
            SELECT ip, port, code, severity, points, evidence
            FROM findings
            WHERE scan_id = ?
            ORDER BY
                CASE severity
                    WHEN 'high' THEN 0
                    WHEN 'medium' THEN 1
                    WHEN 'low' THEN 2
                    ELSE 3
                END,
                ip, port, code
            """,
            (scan_id,),
        ).fetchall()
        result["findings"] = [dict(finding) for finding in findings]
        return result


def _port_key(port: dict[str, Any]) -> tuple[str, int]:
    return str(port["protocol"]), int(port["port"])


def _finding_key(finding: dict[str, Any]) -> tuple[str, int | None, str]:
    return (
        str(finding["ip"]),
        finding["port"],
        str(finding["code"]),
    )


def compare(
    id_a: int,
    id_b: int,
    db_path: str | Path | None = None,
) -> dict[str, Any]:
    """Compare two scans, matching devices by IP address."""

    before = get_scan(id_a, db_path)
    after = get_scan(id_b, db_path)
    if before["status"] != "ok" or after["status"] != "ok":
        raise ValueError("Both scans must be valid before they can be compared.")

    before_devices = {device["ip"]: device for device in before["devices"]}
    after_devices = {device["ip"]: device for device in after["devices"]}
    new_devices = sorted(set(after_devices) - set(before_devices))
    removed_devices = sorted(set(before_devices) - set(after_devices))

    def ports_by_ip(devices: dict[str, dict[str, Any]]) -> set[tuple[str, int, str]]:
        return {
            (ip, *_port_key(port))
            for ip, device in devices.items()
            for port in device["ports"]
        }

    opened = ports_by_ip(after_devices) - ports_by_ip(before_devices)
    closed = ports_by_ip(before_devices) - ports_by_ip(after_devices)
    opened_ports = [
        {"ip": ip, "port": port, "protocol": protocol}
        for ip, protocol, port in opened
    ]
    closed_ports = [
        {"ip": ip, "port": port, "protocol": protocol}
        for ip, protocol, port in closed
    ]

    before_findings = {
        _finding_key(finding): finding for finding in before["findings"]
    }
    after_findings = {
        _finding_key(finding): finding for finding in after["findings"]
    }

    def finding_summary(key: tuple[str, int | None, str]) -> dict[str, Any]:
        ip, port, code = key
        return {"ip": ip, "port": port, "code": code}

    new_findings = [
        finding_summary(key)
        for key in after_findings.keys() - before_findings.keys()
    ]
    resolved_findings = [
        finding_summary(key)
        for key in before_findings.keys() - after_findings.keys()
    ]
    key_order = lambda item: (item["ip"], item["port"] is None, item["port"] or -1, item["code"])
    return {
        "score_before": before["network_score"],
        "score_after": after["network_score"],
        "new_devices": new_devices,
        "removed_devices": removed_devices,
        "opened_ports": sorted(opened_ports, key=lambda item: (item["ip"], item["port"], item["protocol"])),
        "closed_ports": sorted(closed_ports, key=lambda item: (item["ip"], item["port"], item["protocol"])),
        "new_findings": sorted(new_findings, key=key_order),
        "resolved_findings": sorted(resolved_findings, key=key_order),
    }


def delete_history(db_path: str | Path | None = None) -> None:
    """Delete every saved scan and its related data."""

    with _connect(db_path) as connection:
        connection.execute("DELETE FROM ai_answers")
        connection.execute("DELETE FROM device_ports")
        connection.execute("DELETE FROM devices")
        connection.execute("DELETE FROM findings")
        connection.execute("DELETE FROM scans")
