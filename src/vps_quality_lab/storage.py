"""Private, atomic run records and process-owned locks."""

import fcntl
import hashlib
import json
import os
import tempfile
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path

from .models import RunResult


class LabError(Exception):
    def __init__(self, message: str, code: int = 1):
        super().__init__(message)
        self.code = code


def now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def digest(data) -> str:
    return hashlib.sha256(json.dumps(data, sort_keys=True, default=str).encode()).hexdigest()


def private_dir(path: Path):
    if path.is_symlink():
        raise LabError("Refusing a symlink as private directory")
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    path.chmod(0o700)
    return path


def write_private(path: Path, data: str | bytes):
    private_dir(path.parent)
    if path.is_symlink():
        raise LabError("Refusing to replace a symlink")
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=".writing-")
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(data.encode() if isinstance(data, str) else data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(tmp, path)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)


def write_json(path: Path, data):
    write_private(path, json.dumps(data, indent=2, ensure_ascii=False, default=str) + "\n")


def load_run(path: Path):
    return RunResult.model_validate_json((path / "state.json").read_text())


@contextmanager
def run_lock(path: Path):
    private_dir(path)
    with (path / ".lock").open("a+") as stream:
        os.chmod(stream.name, 0o600)
        try:
            fcntl.flock(stream, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise LabError("This run is already active", 5) from exc
        try:
            yield
        finally:
            fcntl.flock(stream, fcntl.LOCK_UN)
