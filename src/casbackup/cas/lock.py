from __future__ import annotations

import json
import os
import socket
import time

from .backend.base import Backend, BlobNotFound

LOCK_NAME = "locks/repo.lock"


class LockError(Exception):
    """Lock cannot be acquired; message names the current holder."""


def _pid_alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


class RepositoryLock:
    def __init__(
        self, backend: Backend, operation: str = "write", force: bool = False
    ) -> None:
        self._backend = backend
        self._operation = operation
        self._force = force
        self._token = os.urandom(8).hex()  # distinguishes us from any
        self._held = False  # other same-PID reincarnation

    # -- payload ----------------------------------------------------------

    def _payload(self) -> bytes:
        return json.dumps(
            {
                "pid": os.getpid(),
                "hostname": socket.gethostname(),
                "timestamp": time.time(),
                "operation": self._operation,
                "token": self._token,
            }
        ).encode()

    @staticmethod
    def _read(backend: Backend) -> dict | None:
        try:
            raw = backend.get_bytes(LOCK_NAME)
        except BlobNotFound:
            return None
        try:
            return json.loads(raw)
        except (json.JSONDecodeError, UnicodeDecodeError):
            return {
                "corrupt": True,
                "hostname": "?",
                "pid": -1,
                "timestamp": 0,
                "token": None,
            }

    # -- acquisition --------------------------------------------------------

    def acquire(self) -> None:
        existing = self._read(self._backend)

        if existing is not None and not self._force:
            stale = existing.get("corrupt") or (
                existing.get("hostname") == socket.gethostname()
                and not _pid_alive(int(existing.get("pid", -1)))
            )
            if not stale:
                age = time.time() - float(existing.get("timestamp", 0))
                raise LockError(
                    f"repository locked by pid {existing.get('pid')} on "
                    f"{existing.get('hostname')} "
                    f"(operation={existing.get('operation')!r}, "
                    f"age={age:.0f}s). If that host/process is known "
                    f"dead, retry with force."
                )

        self._backend.put_bytes(LOCK_NAME, self._payload())

        current = self._read(self._backend)
        if current is None or current.get("token") != self._token:
            raise LockError("lost lock race to a concurrent process")
        self._held = True

    def refresh(self) -> None:
        if not self._held:
            raise LockError("refresh() without holding the lock")
        self._backend.put_bytes(LOCK_NAME, self._payload())

    def release(self) -> None:
        if not self._held:
            return
        # Only remove OUR lock: a --force party may have replaced it.
        current = self._read(self._backend)
        if current is not None and current.get("token") == self._token:
            try:
                self._backend.delete(LOCK_NAME)
            except BlobNotFound:
                pass
        self._held = False

    # -- context manager -------------------------------------------------------

    def __enter__(self) -> "RepositoryLock":
        self.acquire()
        return self

    def __exit__(self, *exc) -> None:
        self.release()
