"""Restore (decision 16: full snapshot + single file, streaming).

THE READ PATH, END TO END
=========================
    snapshot blob -> root tree id -> walk nodes -> per file:
        for each chunk id in order:
            store.get(id)      [AEAD verify + plaintext re-hash]
            write to output; feed whole-file hasher
        compare whole-file hash to manifest's file_hash

STREAMING means chunk-at-a-time: peak memory per file is one chunk
(<= 256 KiB), independent of file size. Chunks are fetched by ranged
reads from packs (packfile.read_blob) — restoring one 4 KiB file from
a repository of terabytes reads a few KiB of pack data plus the tree
nodes on its path. That property IS decision 16's single-file
requirement; a design that read whole packs would technically work
and practically fail.

THREE INTEGRITY LAYERS ON EVERY RESTORED BYTE (decision 17)
===========================================================
1. AEAD tag           — storage-level tampering/corruption (crypto.py)
2. chunk id re-hash   — end-to-end per chunk (objectstore.py)
3. whole-file hash    — chunk SEQUENCE correctness (this file):
                        catches ordering bugs where every chunk is
                        individually valid but assembly is wrong.
Failure of any layer aborts THAT file with a hard error and a partial-
file cleanup; restore continues with remaining files and reports. A
restore tool that dies entirely on one bad chunk converts partial
data loss into total data loss.

WRITE-SIDE SAFETY
=================
- Target files are written to a temp name, fsync'd, renamed — the
  local backend's atomic-publish discipline reused on the RESTORE
  side. An interrupted restore leaves no half-written files under
  final names.
- refuse_overwrite: restoring into a nonempty location silently
  replacing files is an operator disaster; default refuses if the
  target entry exists, --force at CLI overrides.
- Directory metadata applied bottom-up AFTER contents (metadata.py
  ordering rationale): collected during the walk, applied in reverse
  depth order at the end.

SINGLE-FILE RESTORE
===================
Navigates the tree by path components — O(depth) node loads, no full
walk. The Merkle structure makes partial restore cheap by design;
this function is the payoff of decision 8 over a flat manifest.
"""

from __future__ import annotations

import os
import tempfile
from dataclasses import dataclass, field
from pathlib import Path

from ..cas import hasher
from ..cas.objectstore import ObjectStore, ObjectStoreError
from .manifest import TreeEntry, load_tree_node
from .metadata import TYPE_DIR, TYPE_FILE, TYPE_SYMLINK


class RestoreError(Exception):
    pass


@dataclass
class RestoreReport:
    files: int = 0
    dirs: int = 0
    symlinks: int = 0
    bytes_written: int = 0
    failed: list[tuple[str, str]] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)


def _write_file_streaming(store: ObjectStore, entry: TreeEntry,
                          target: Path, report: RestoreReport) -> None:
    """Chunk-at-a-time write with layer-3 verification and atomic
    publish. Raises on integrity failure; caller records and moves on."""
    fhash = hasher.StreamingHasher()
    fd, tmp = tempfile.mkstemp(dir=target.parent, prefix=".restore-")
    try:
        with os.fdopen(fd, "wb") as out:
            for cid in entry.chunks or ():
                data = store.get(cid)              # layers 1 + 2
                fhash.update(data)
                out.write(data)
                report.bytes_written += len(data)
            out.flush()
            os.fsync(out.fileno())

        if fhash.digest() != entry.file_hash:      # layer 3
            raise RestoreError(
                "whole-file hash mismatch after chunk assembly "
                "(chunk ordering corruption)")

        os.rename(tmp, target)
    except BaseException:
        try:
            os.unlink(tmp)                          # no partials
        except OSError:
            pass
        raise


def restore_tree(store: ObjectStore, root_tree: bytes, target: Path,
                 refuse_overwrite: bool = True) -> RestoreReport:
    """Full-snapshot restore of a tree into `target` (created if
    absent). See module docstring for guarantees."""
    report = RestoreReport()
    target = Path(target)
    target.mkdir(parents=True, exist_ok=True)

    # (depth, path, meta) for the bottom-up metadata pass
    dir_meta: list[tuple[int, Path, TreeEntry]] = []

    def recurse(tree_id: bytes, out_dir: Path, depth: int) -> None:
        for entry in load_tree_node(store, tree_id):
            dest = out_dir / entry.name
            rel = str(dest.relative_to(target))

            if refuse_overwrite and (dest.exists() or dest.is_symlink()):
                report.failed.append((rel, "target exists (use --force)"))
                continue

            try:
                if entry.meta.type == TYPE_DIR:
                    dest.mkdir(exist_ok=True)
                    report.dirs += 1
                    dir_meta.append((depth, dest, entry))
                    recurse(entry.tree, dest, depth + 1)   # type: ignore[arg-type]
                elif entry.meta.type == TYPE_FILE:
                    _write_file_streaming(store, entry, dest, report)
                    report.warnings += entry.meta.apply(dest)
                    report.files += 1
                elif entry.meta.type == TYPE_SYMLINK:
                    if dest.is_symlink() or dest.exists():
                        dest.unlink()
                    os.symlink(entry.meta.link_target, dest)  # type: ignore[arg-type]
                    report.warnings += entry.meta.apply(dest)
                    report.symlinks += 1
            except (OSError, ObjectStoreError, RestoreError) as exc:
                report.failed.append((rel, str(exc)))

    recurse(root_tree, target, 0)

    # deepest-first: children's writes no longer disturb parent mtimes
    for _depth, path, entry in sorted(dir_meta, key=lambda t: -t[0]):
        report.warnings += entry.meta.apply(path)

    return report


def restore_single(store: ObjectStore, root_tree: bytes, rel_path: str,
                   target: Path,
                   refuse_overwrite: bool = True) -> RestoreReport:
    """Restore ONE path from a snapshot. O(depth) tree navigation."""
    report = RestoreReport()
    parts = [p for p in rel_path.split("/") if p]
    if not parts:
        raise RestoreError("empty path")

    # descend to the entry
    tree_id = root_tree
    entry: TreeEntry | None = None
    for i, part in enumerate(parts):
        entries = {e.name: e for e in load_tree_node(store, tree_id)}
        entry = entries.get(part)
        if entry is None:
            raise RestoreError(f"path not in snapshot: "
                               f"{'/'.join(parts[:i + 1])!r}")
        if i < len(parts) - 1:
            if entry.meta.type != TYPE_DIR:
                raise RestoreError(
                    f"{'/'.join(parts[:i + 1])!r} is not a directory")
            tree_id = entry.tree            # type: ignore[assignment]

    assert entry is not None
    target = Path(target)
    target.parent.mkdir(parents=True, exist_ok=True)

    if refuse_overwrite and (target.exists() or target.is_symlink()):
        raise RestoreError(f"target exists: {target} (use --force)")

    if entry.meta.type == TYPE_FILE:
        _write_file_streaming(store, entry, target, report)
        report.warnings += entry.meta.apply(target)
        report.files += 1
    elif entry.meta.type == TYPE_SYMLINK:
        os.symlink(entry.meta.link_target, target)   # type: ignore[arg-type]
        report.warnings += entry.meta.apply(target)
        report.symlinks += 1
    else:                                   # a directory: restore subtree
        sub = restore_tree(store, entry.tree, target,   # type: ignore[arg-type]
                           refuse_overwrite=refuse_overwrite)
        report.files += sub.files
        report.dirs += sub.dirs + 1
        report.symlinks += sub.symlinks
        report.bytes_written += sub.bytes_written
        report.failed += sub.failed
        report.warnings += sub.warnings + entry.meta.apply(target)

    return report
