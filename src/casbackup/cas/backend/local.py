from __future__ import annotations

import os
import shutil
import tempfile
from pathlib import Path
from typing import Iterator

from .base import Backend, BackendError, BlobNotFound


class LocalBackend(Backend):
    def __init__(self, root: str | Path) -> None:
        self._root = Path(root).resolve()
        self._root.mkdir(parents=True, exist_ok=True)

    # -- internals -----------------------------------------------------------

    def _resolve(self, name: str) -> Path:
        """Map a blob name to a filesystem path, safely."""
        if not name or name.startswith("/") or ".." in name.split("/"):
            raise BackendError(f"illegal blob name: {name!r}")
        path = (self._root / name).resolve()
        # resolve() collapses symlink tricks; verify containment after.
        if not path.is_relative_to(self._root):
            raise BackendError(f"blob name escapes repository: {name!r}")
        return path

    @staticmethod
    def _fsync_dir(directory: Path) -> None:
        """Durably commit directory mutations (step 4)."""
        fd = os.open(directory, os.O_RDONLY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)

    def _atomic_publish(self, tmp_path: Path, final: Path) -> None:
        """Steps 3-4: rename into place, fsync the directory."""
        os.rename(tmp_path, final)
        self._fsync_dir(final.parent)

    # -- writes ----------------------------------------------------------------

    def put_bytes(self, name: str, data: bytes) -> None:
        final = self._resolve(name)
        final.parent.mkdir(parents=True, exist_ok=True)
        # Step 1: temp file in the TARGET directory (same filesystem).
        fd, tmp = tempfile.mkstemp(dir=final.parent, prefix=".tmp-")
        try:
            with os.fdopen(fd, "wb") as f:
                f.write(data)
                f.flush()
                os.fsync(f.fileno())  # step 2
            self._atomic_publish(Path(tmp), final)
        except OSError as exc:
            try:
                os.unlink(tmp)
            except OSError:
                pass
            raise BackendError(f"put_bytes({name!r}): {exc}") from exc

    def put_file(self, name: str, local_path: str) -> None:
        """Publish an existing local file (pack staging output).

        The source may be on a different filesystem (system tmp), so
        it is COPIED into the target directory first — restoring the
        same-filesystem precondition — then fsync'd and renamed.
        """
        final = self._resolve(name)
        final.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp = tempfile.mkstemp(dir=final.parent, prefix=".tmp-")
        try:
            with os.fdopen(fd, "wb") as dst, open(local_path, "rb") as src:
                shutil.copyfileobj(src, dst, length=1024 * 1024)
                dst.flush()
                os.fsync(dst.fileno())  # step 2
            self._atomic_publish(Path(tmp), final)
        except OSError as exc:
            try:
                os.unlink(tmp)
            except OSError:
                pass
            raise BackendError(f"put_file({name!r}): {exc}") from exc

    # -- reads -------------------------------------------------------------------

    def get_bytes(self, name: str) -> bytes:
        path = self._resolve(name)
        try:
            return path.read_bytes()
        except FileNotFoundError:
            raise BlobNotFound(name) from None
        except OSError as exc:
            raise BackendError(f"get_bytes({name!r}): {exc}") from exc

    def get_range(self, name: str, offset: int, length: int) -> bytes:
        """Ranged read via pread — no seek state, one syscall.

        Enforces exact-length results: a short read here means the
        index and the pack disagree about geometry, which upper layers
        must treat as corruption, not as EOF (base.py contract).
        """
        path = self._resolve(name)
        try:
            fd = os.open(path, os.O_RDONLY)
        except FileNotFoundError:
            raise BlobNotFound(name) from None
        except OSError as exc:
            raise BackendError(f"get_range({name!r}): {exc}") from exc
        try:
            data = os.pread(fd, length, offset)
        except OSError as exc:
            raise BackendError(f"get_range({name!r}): {exc}") from exc
        finally:
            os.close(fd)
        if len(data) != length:
            raise BackendError(
                f"get_range({name!r}): wanted {length} bytes at {offset}, "
                f"got {len(data)} — index/pack geometry mismatch"
            )
        return data

    # -- probes --------------------------------------------------------------------

    def exists(self, name: str) -> bool:
        return self._resolve(name).is_file()

    def size(self, name: str) -> int:
        path = self._resolve(name)
        try:
            return path.stat().st_size
        except FileNotFoundError:
            raise BlobNotFound(name) from None

    # -- enumeration -----------------------------------------------------------------

    def list(self, prefix: str) -> Iterator[str]:
        """Walk under the prefix's directory; emit names relative to
        root, skipping in-flight temp files (.tmp-*), which are
        implementation detail, not blobs."""
        base = (
            self._root / prefix
            if not prefix
            else self._resolve(prefix.rstrip("/"))
            if "/" in prefix or prefix
            else self._root
        )
        # Simpler and correct: walk root, filter by string prefix.
        for dirpath, _dirs, files in os.walk(self._root):
            for fname in files:
                if fname.startswith(".tmp-"):
                    continue
                rel = str(Path(dirpath, fname).relative_to(self._root))
                if rel.startswith(prefix):
                    yield rel

    # -- deletion --------------------------------------------------------------------

    def delete(self, name: str) -> None:
        path = self._resolve(name)
        try:
            path.unlink()
        except FileNotFoundError:
            raise BlobNotFound(name) from None
        except OSError as exc:
            raise BackendError(f"delete({name!r}): {exc}") from exc
        self._fsync_dir(path.parent)  # deletion durable too
