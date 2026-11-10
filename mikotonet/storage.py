"""POSIX single-writer locking and fail-closed, sync-written JSON records."""
import fcntl
import json
import os
from pathlib import Path


def records(path):
    path = Path(path)
    if path.exists():
        with path.open("rb") as handle:
            for line in handle:
                if not line.endswith(b"\n"):
                    raise ValueError("truncated journal; restore before continuing")
                yield json.loads(line)


def append(path, record):
    from .engine import canonical
    path = Path(path)
    # Directory fsync makes a newly created filename durable before acknowledgment.
    with path.open("ab") as handle:
        os.chmod(path, 0o600)
        handle.write(canonical(record) + b"\n")
        handle.flush()
        os.fsync(handle.fileno())
    directory = os.open(path.parent, os.O_RDONLY)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)


class WriterLock:
    def __init__(self, path):
        self.handle = Path(path).open("a+b")
        try:
            fcntl.flock(self.handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            self.handle.close()
            raise ValueError("storage already has a writer") from None

    def close(self):
        self.handle.close()
