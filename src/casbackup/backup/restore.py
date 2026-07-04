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


def _write_file_streaming(
    store: ObjectStore, entry: TreeEntry, target: Path, report: RestoreReport
) -> None:
    fhash = hasher.StreamingHasher()
    fd, tmp = tempfile.mkstemp(dir=target.parent, prefix=".restore-")
    try:
        with os.fdopen(fd, "wb") as out:
            for cid in entry.chunks or ():
                data = store.get(cid)  # layers 1 + 2
                fhash.update(data)
                out.write(data)
                report.bytes_written += len(data)
            out.flush()
            os.fsync(out.fileno())

        if fhash.digest() != entry.file_hash:  # layer 3
            raise RestoreError(
                "whole-file hash mismatch after chunk assembly "
                "(chunk ordering corruption)"
            )

        os.rename(tmp, target)
    except BaseException:
        try:
            os.unlink(tmp)  # no partials
        except OSError:
            pass
        raise


def restore_tree(
    store: ObjectStore, root_tree: bytes, target: Path, refuse_overwrite: bool = True
) -> RestoreReport:
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
                    recurse(entry.tree, dest, depth + 1)  # type: ignore[arg-type]
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


def restore_single(
    store: ObjectStore,
    root_tree: bytes,
    rel_path: str,
    target: Path,
    refuse_overwrite: bool = True,
) -> RestoreReport:
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
            raise RestoreError(f"path not in snapshot: {'/'.join(parts[: i + 1])!r}")
        if i < len(parts) - 1:
            if entry.meta.type != TYPE_DIR:
                raise RestoreError(f"{'/'.join(parts[: i + 1])!r} is not a directory")
            tree_id = entry.tree  # type: ignore[assignment]

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
        os.symlink(entry.meta.link_target, target)  # type: ignore[arg-type]
        report.warnings += entry.meta.apply(target)
        report.symlinks += 1
    else:  # a directory: restore subtree
        sub = restore_tree(
            store,
            entry.tree,
            target,  # type: ignore[arg-type]
            refuse_overwrite=refuse_overwrite,
        )
        report.files += sub.files
        report.dirs += sub.dirs + 1
        report.symlinks += sub.symlinks
        report.bytes_written += sub.bytes_written
        report.failed += sub.failed
        report.warnings += sub.warnings + entry.meta.apply(target)

    return report
