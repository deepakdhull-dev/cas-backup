"""Repository locking (decision 15: lock file with PID, timestamp,
hostname).

WHAT THE LOCK PROTECTS AGAINST
==============================
Two writers mutating the repository concurrently: two backup runs
interleaving pack writes and index transactions, or a backup racing a
`prune` (GC deleting packs the backup is referencing). Reads are
harmless; writes racing writes or writes racing GC can corrupt
logical state even though each individual blob write is atomic.

WHY METADATA IN THE LOCK, NOT JUST A LOCK FILE'S EXISTENCE
==========================================================
A bare lock file has a fatal operational flaw: the process holding it
can die (crash, SIGKILL, power loss) without removing it, and then
every future operation deadlocks on a lock nobody holds. The fix is
storing WHO holds it:

    { pid, hostname, timestamp, operation }

A later process finding the lock can reason about staleness:

- Same hostname + PID no longer alive  -> holder is dead -> STALE,
  safe to break and take over.
- Same hostname + PID alive            -> genuinely held -> fail with
  a message naming the holder.
- DIFFERENT hostname                   -> cannot probe a remote PID.
  Never auto-break; report holder and age, require --force from a
  human who knows the other machine's state. Guessing here is how
  two machines end up writing simultaneously.

WHY flock(2) IS NOT USED INSTEAD
================================
flock would hand the OS the whole liveness problem (kernel drops the
lock when the holder dies — elegant). Rejected because it only works
on LOCAL files: the lock must live in the repository itself, and the
repository may sit behind any Backend (NFS today, S3 later). flock
over NFS is historically unreliable; flock over S3 is meaningless.
A lock-as-blob with staleness metadata works uniformly over anything
implementing Backend. This is the same reasoning restic uses.

HONEST LIMITATION — TOCTOU WINDOW
=================================
The acquire sequence is: read existing lock -> decide -> write ours ->
re-read and verify we won. Between any two steps another process can
act; the verify-after-write shrinks the race window to milliseconds
but cannot eliminate it without a compare-and-swap primitive, which
the Backend interface cannot promise (plain filesystems lack it;
S3 gained conditional puts only recently). Accepted for v1 because:
single-user tool (decision 15's scope), the window is tiny, and the
consequence of the residual race is two holders — the same state a
--force misuse produces. Documented rather than hidden. A real CAS
primitive per-backend is the correct future fix, as a Backend
capability flag.

LEASE-STYLE REFRESH
===================
Long operations refresh the lock's timestamp periodically (refresh()).
Purpose: a human (or tooling) inspecting a lock whose timestamp is
hours old on an unreachable hostname gets evidence for a break-lock
decision. The timestamp is advisory evidence, never proof.
"""

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
    """Is a PID alive on THIS host? kill(pid, 0) sends no signal but
    performs the existence/permission check. EPERM means 'exists but
    not ours' — still alive."""
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


class RepositoryLock:
    """Advisory single-writer lock stored as a backend blob.

    Usage:
        with RepositoryLock(backend, operation="backup"):
            ... mutate repository ...

    force=True skips holder checks entirely — the human override for
    the cross-host case. Never the default anywhere.
    """

    def __init__(self, backend: Backend, operation: str = "write",
                 force: bool = False) -> None:
        self._backend = backend
        self._operation = operation
        self._force = force
        self._token = os.urandom(8).hex()   # distinguishes us from any
        self._held = False                  # other same-PID reincarnation

    # -- payload ----------------------------------------------------------

    def _payload(self) -> bytes:
        return json.dumps({
            "pid": os.getpid(),
            "hostname": socket.gethostname(),
            "timestamp": time.time(),
            "operation": self._operation,
            "token": self._token,
        }).encode()

    @staticmethod
    def _read(backend: Backend) -> dict | None:
        try:
            raw = backend.get_bytes(LOCK_NAME)
        except BlobNotFound:
            return None
        try:
            return json.loads(raw)
        except (json.JSONDecodeError, UnicodeDecodeError):
            # Unparseable lock: treat as stale garbage — it cannot
            # name a holder, so it cannot be respected meaningfully.
            return {"corrupt": True, "hostname": "?", "pid": -1,
                    "timestamp": 0, "token": None}

    # -- acquisition --------------------------------------------------------

    def acquire(self) -> None:
        existing = self._read(self._backend)

        if existing is not None and not self._force:
            stale = (
                existing.get("corrupt")
                or (existing.get("hostname") == socket.gethostname()
                    and not _pid_alive(int(existing.get("pid", -1))))
            )
            if not stale:
                age = time.time() - float(existing.get("timestamp", 0))
                raise LockError(
                    f"repository locked by pid {existing.get('pid')} on "
                    f"{existing.get('hostname')} "
                    f"(operation={existing.get('operation')!r}, "
                    f"age={age:.0f}s). If that host/process is known "
                    f"dead, retry with force.")
            # stale: fall through and overwrite

        self._backend.put_bytes(LOCK_NAME, self._payload())

        # Verify-after-write: did we actually win? (TOCTOU shrink —
        # see module docstring for why this cannot be airtight.)
        current = self._read(self._backend)
        if current is None or current.get("token") != self._token:
            raise LockError("lost lock race to a concurrent process")
        self._held = True

    def refresh(self) -> None:
        """Re-stamp the lock's timestamp mid-operation (lease-style)."""
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
