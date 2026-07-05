"""File metadata capture and restoration (decision 9: standard tier —
permissions, owner/group, mtime).

WHY METADATA IS ITS OWN PROBLEM
===============================
Chunks reconstruct file CONTENT. A restored file with the wrong mode
(private key restored world-readable), wrong owner (root-owned config
restored as the backup user), or wrong mtime (build systems and sync
tools keyed on mtime misfire) is a wrong restore even with perfect
bytes. Backup semantics = content + metadata; tar got this right in
1979 and every serious tool since preserves both.

WHAT lstat GIVES AND WHY lstat, NOT stat
========================================
stat() FOLLOWS symlinks: stat("/backup/link-to-etc-shadow") reports
on /etc/shadow. A scanner using stat() dereferences every link —
backing up link TARGETS (possibly outside the source tree, possibly
in a cycle) instead of the links themselves. lstat() reports on the
link itself. Scanners use lstat, unconditionally. This single-
character API difference is a classic backup-tool security bug.

SYMLINK POLICY — APPLIED INTERPRETATION, FLAGGED FOR SIGN-OFF
=============================================================
Decision 9's "standard" tier listed perms/owner/mtime; symlinks were
listed under "full". A scanner must still DO something on
encountering one, and the three options are: follow (rejected —
security hazard above, plus cycles), skip silently (rejected — silent
data loss, a backup tool's cardinal sin), or record the link target
string (chosen — one lstat + one readlink, no traversal, restores
faithfully). Recording targets is the minimal non-destructive option,
NOT full symlink semantics (no ownership-of-link preservation
subtleties, no hardlink identity — see below). Veto reverts to
skip-with-warning.

HARDLINKS (excluded per decision 9)
===================================
Two hardlinked names are stored as two independent files. Content
dedup makes the storage cost zero (identical bytes -> identical
chunks), but restore produces two unlinked copies: link identity
(st_nlink, shared inode) is not preserved. Documented limitation;
full tier would track (st_dev, st_ino) pairs.

SPECIAL FILES (sockets, FIFOs, device nodes)
============================================
Skipped, reported. Their "content" is not bytes on disk; device nodes
require root to recreate. Every mainstream tool defaults similarly.

RESTORE-SIDE REALITIES
======================
- chown REQUIRES PRIVILEGE. Unprivileged restore of root-owned files
  cannot restore ownership (EPERM). Policy: attempt, degrade to a
  warning, never fail the restore. A readable restore with wrong
  owner beats no restore; the warning preserves operator awareness.
- ORDERING: directory mtimes must be applied AFTER the directory's
  contents are written — creating a child updates the parent's mtime,
  clobbering a just-applied value. Restore therefore applies dir
  metadata in a second, bottom-up pass. File mtimes are safe
  immediately after content write.
- mtime carried as NANOSECONDS (st_mtime_ns / utime ns=): the float
  seconds API loses precision; tools diffing at ns granularity
  (make, rsync -a comparisons) would see phantom changes.
"""

from __future__ import annotations

import os
import stat
from dataclasses import dataclass
from pathlib import Path

# Entry type tags — part of the manifest format (stable strings).
TYPE_FILE = "file"
TYPE_DIR = "dir"
TYPE_SYMLINK = "symlink"


@dataclass(frozen=True)
class FileMeta:
    """Metadata for one filesystem entry, capture-side complete.

    size is informational for files (restore truth is the chunk list;
    size lets `list` and progress reporting avoid chunk math).
    link_target is set only for TYPE_SYMLINK.
    """
    type: str
    mode: int            # permission bits only (see from_path)
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
            return None   # socket/fifo/device — skipped by policy

        return FileMeta(
            type=etype,
            # S_IMODE strips the file-type bits, keeping permission +
            # suid/sgid/sticky bits — the part chmod can apply back.
            mode=stat.S_IMODE(m),
            uid=st.st_uid,
            gid=st.st_gid,
            mtime_ns=st.st_mtime_ns,
            size=st.st_size if stat.S_ISREG(m) else 0,
            link_target=target,
        )

    # -- restore -----------------------------------------------------------

    def apply(self, path: Path) -> list[str]:
        """Apply metadata to a restored entry. Returns warnings
        (never raises for privilege problems — see module docstring).

        Symlinks: the link itself gets no chmod (Linux ignores link
        modes) and mtime via follow_symlinks=False where supported.
        """
        warnings: list[str] = []

        # ownership first: chown can clear suid/sgid bits, so mode
        # must be applied AFTER chown to survive it.
        try:
            os.lchown(path, self.uid, self.gid)
        except PermissionError:
            warnings.append(
                f"{path}: cannot restore ownership {self.uid}:{self.gid} "
                f"(not privileged) — kept current owner")
        except OSError as exc:
            warnings.append(f"{path}: chown failed: {exc}")

        if self.type != TYPE_SYMLINK:
            try:
                os.chmod(path, self.mode)
            except OSError as exc:
                warnings.append(f"{path}: chmod failed: {exc}")

        try:
            os.utime(path, ns=(self.mtime_ns, self.mtime_ns),
                     follow_symlinks=False)
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
