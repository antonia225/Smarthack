"""Keep application state out of the developer's database and lock file."""
import pytest

from netcheck import history, service


@pytest.fixture(autouse=True)
def isolated_application_state(tmp_path, monkeypatch):
    monkeypatch.setattr(history, "DB_PATH", tmp_path / "netcheck.db")
    monkeypatch.setattr(service, "_SCAN_LOCK_PATH", tmp_path / "scan.lock")
