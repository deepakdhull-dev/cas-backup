from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

from ..cas import chunker, hasher
from ..cas.objectstore import ObjectStore
from .manifest import TreeEntry, store_tree_node
from .metadata import TYPE_DIR, TYPE_FILE, TYPE_SYMLINK, FileMeta


@dataclass
class ScanReport:
    files: int = 0
    dirs: int = 0
    symlinks: int = 0
    bytes_read: int = 0
    chunks_new: int = 0  # approximate: counts store misses
    skipped: list[tuple[str, str]] = field(default_factory=list)


ExcludeFn = Callable[[str], bool]  # relative path -> skip?


def _scan_file(
    store: ObjectStore, path: Path, report: ScanReport
) -> tuple[tuple[bytes, ...], bytes]:
    ids: list[bytes] = []
    fhash = hasher.StreamingHasher()
    with open(path, "rb") as f:
        for chunk in chunker.chunk_stream(f):
            fhash.update(chunk.data)
            new = not store.has(hasher.chunk_id(chunk.data))
            ids.append(store.put(chunk.data))
            report.bytes_read += len(chunk.data)
            if new:
                report.chunks_new += 1
    return tuple(ids), fhash.digest()


def scan_directory(
    store: ObjectStore, root: Path, exclude: ExcludeFn | None = None, _rel: str = ""
) -> tuple[bytes, ScanReport]:
    report = ScanReport()
    root_id = _scan_dir_recursive(store, Path(root), exclude, _rel, report)
    return root_id, report


def _scan_dir_recursive(
    store: ObjectStore,
    dirpath: Path,
    exclude: ExcludeFn | None,
    rel: str,
    report: ScanReport,
) -> bytes:
    entries: list[TreeEntry] = []

    try:
        names = sorted(os.listdir(dirpath))  # determinism
    except OSError as exc:
        report.skipped.append((rel or ".", f"unreadable dir: {exc}"))
        names = []

    for name in names:
        child = dirpath / name
        child_rel = f"{rel}{name}" if not rel else f"{rel}/{name}"

        if exclude is not None and exclude(child_rel):
            continue

        try:
            meta = FileMeta.from_path(child)
        except OSError as exc:  # vanished / EACCES
            report.skipped.append((child_rel, f"lstat failed: {exc}"))
            continue

        if meta is None:
            report.skipped.append((child_rel, "special file (socket/fifo/device)"))
            continue

        try:
            if meta.type == TYPE_FILE:
                chunks, fhash = _scan_file(store, child, report)
                entries.append(
                    TreeEntry(name=name, meta=meta, chunks=chunks, file_hash=fhash)
                )
                report.files += 1
            elif meta.type == TYPE_DIR:
                tree_id = _scan_dir_recursive(store, child, exclude, child_rel, report)
                entries.append(TreeEntry(name=name, meta=meta, tree=tree_id))
                report.dirs += 1
            elif meta.type == TYPE_SYMLINK:
                entries.append(TreeEntry(name=name, meta=meta))
                report.symlinks += 1
        except OSError as exc:
            report.skipped.append((child_rel, f"read failed: {exc}"))
            continue

    # children durable-ordered before parent (BOTTOM-UP, module doc)
    return store_tree_node(store, entries)
