"""Shared application entry point; clients cannot override lab authorization."""
from contextlib import contextmanager
import errno
import os
from pathlib import Path
from threading import Lock
from uuid import uuid4

from netcheck import scanner


class ScanBusyError(RuntimeError):
    """Another scan is active for this project."""


# A thread lock avoids platform-specific same-process file-lock semantics.
# A fixed project path also covers separate CLI/API processes and output dirs.
_SCAN_LOCK = Lock()
_SCAN_LOCK_PATH = Path(__file__).resolve().parent.parent / ".netcheck-scan.lock"


def _busy():
    return ScanBusyError("O scanare este deja în curs / A scan is already in progress")


@contextmanager
def _cross_process_lock():
    # The file is intentionally retained; unlinking it while other processes
    # have opened it would allow two different inodes to be locked at once.
    # Kernel locks are released on process exit, including crashes.
    with _SCAN_LOCK_PATH.open("a+b") as handle:
        handle.seek(0, os.SEEK_END)
        if handle.tell() == 0:
            handle.write(b"0")
            handle.flush()
        handle.seek(0)
        try:
            if os.name == "nt":
                import msvcrt
                msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                import fcntl
                fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as exc:
            if exc.errno in (errno.EACCES, errno.EAGAIN, errno.EDEADLK):
                raise _busy() from exc
            raise
        try:
            yield
        finally:
            handle.seek(0)
            if os.name == "nt":
                import msvcrt
                msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                import fcntl
                fcntl.flock(handle.fileno(), fcntl.LOCK_UN)


def scan(target: str, *, confirm: bool = False,
         config_path: Path = scanner._DEFAULT_LAB_CONFIG,
         output_dir: Path = Path("scans")) -> scanner.ScanResult:
    if not _SCAN_LOCK.acquire(blocking=False):
        raise _busy()
    try:
        with _cross_process_lock():
            validated = scanner.validate_scan_request(target, confirm=confirm, config_path=config_path)
            output_dir = Path(output_dir)
            output_dir.mkdir(parents=True, exist_ok=True)
            # Each request owns its artifact; no user-controlled filename or overwrite.
            destination = output_dir / f"{uuid4().hex}.xml"
            return scanner.run_scan(validated, str(destination))
    finally:
        _SCAN_LOCK.release()
