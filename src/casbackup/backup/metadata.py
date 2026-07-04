from __future__ import annotations

import os
import stat
from dataclasses import dataclass
from pathlib import Path

TYPE_FILE = "file"
TYPE_DIR = "dir"
TYPE_SYMLINK = "symlink"


@dataclass(frozen=True)
class FileMeta:
    type: str
    mode: int  # permission bits only (see from_path)
    uid: int
    gid: int
    mtime_ns: int
    size: int = 0
    link_target: str | None = None

    # -- capture -----------------------------------------------------------

    @staticmethod
    def from_path(path: Path) -> "FileMeta | None":
        """lstat-based capture. Returns None for special files the
        tool does not back up (caller reports the skip)."""
        st = os.lstat(path)
        m = st.st_mode

        if stat.S_ISREG(m):
            etype, target = TYPE_FILE, None
        elif stat.S_ISDIR(m):
            etype, target = TYPE_DIR, None
        elif stat.S_ISLNK(m):
            etype, target = TYPE_SYMLINK, os.readlink(path)
        else:
            return None  # socket/fifo/device — skipped by policy

        return FileMeta(
            type=etype,
            mode=stat.S_IMODE(m),
            uid=st.st_uid,
            gid=st.st_gid,
            mtime_ns=st.st_mtime_ns,
            size=st.st_size if stat.S_ISREG(m) else 0,
            link_target=target,
        )

    # -- restore -----------------------------------------------------------

    def apply(self, path: Path) -> list[str]:
        warnings: list[str] = []

        try:
            os.lchown(path, self.uid, self.gid)
        except PermissionError:
            warnings.append(
                f"{path}: cannot restore ownership {self.uid}:{self.gid} "
                f"(not privileged) — kept current owner"
            )
        except OSError as exc:
            warnings.append(f"{path}: chown failed: {exc}")

        if self.type != TYPE_SYMLINK:
            try:
                os.chmod(path, self.mode)
            except OSError as exc:
                warnings.append(f"{path}: chmod failed: {exc}")

        try:
            os.utime(path, ns=(self.mtime_ns, self.mtime_ns), follow_symlinks=False)
        except (NotImplementedError, OSError) as exc:
            warnings.append(f"{path}: mtime restore failed: {exc}")

        return warnings

    # -- serialization (manifest format) -------------------------------------

    def to_dict(self) -> dict:
        d = {
            "type": self.type,
            "mode": self.mode,
            "uid": self.uid,
            "gid": self.gid,
            "mtime_ns": self.mtime_ns,
        }
        if self.type == TYPE_FILE:
            d["size"] = self.size
        if self.link_target is not None:
            d["link_target"] = self.link_target
        return d

    @staticmethod
    def from_dict(d: dict) -> "FileMeta":
        return FileMeta(
            type=d["type"],
            mode=d["mode"],
            uid=d["uid"],
            gid=d["gid"],
            mtime_ns=d["mtime_ns"],
            size=d.get("size", 0),
            link_target=d.get("link_target"),
        )
