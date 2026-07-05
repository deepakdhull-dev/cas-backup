"""Directory scanner: filesystem -> chunks -> Merkle tree (the write
path of a backup).

PIPELINE PER REGULAR FILE
=========================
    open -> chunk_stream (CDC, bounded memory)
         -> per chunk: store.put(chunk)      [dedup inside put]
         -> StreamingHasher accumulates the whole-file hash
    -> TreeEntry(chunks=[ids...], file_hash=...)

Chunking and whole-file hashing share ONE read pass: each chunk's
bytes feed the file hasher as they are chunked. A 20 GiB file is read
once, held ~256 KiB at a time.

TREE CONSTRUCTION IS BOTTOM-UP BY NECESSITY
===========================================
A directory node contains its children's ids, so children must be
stored before the parent can even be SERIALIZED. scan_directory
recurses depth-first: leaves stored first, then each directory node
on the way back up, root id emitted last. This ordering also means a
crash mid-scan strands only orphan chunks (GC food), never a root
that references missing children — the root does not exist until
everything under it does. The write-ordering discipline appears a
third time (packs -> index; store -> manifest; children -> parent).

DETERMINISTIC WALK ORDER
========================
Children processed in sorted(name) order. os.scandir order is
filesystem-dependent (inode order on ext4, btree order on XFS);
unsorted walks would build differently-ordered — hence differently-
ID'd — nodes for identical directories on different machines or even
different runs, silently destroying tree-level dedup. Sorting also
matches the sorted-entries canonical form (manifest.py), keeping
scan order and serialization order aligned.

WHAT GETS SKIPPED, AND LOUDLY
=============================
- Special files (metadata.py returns None): reported per path.
- Unreadable entries (EACCES, vanished mid-scan): reported, scan
  continues. A backup run must not die at 99% on one bad file; it
  must also never pretend the file was saved. ScanReport carries the
  full skip list; the CLI surfaces it; a nonzero skip count is the
  operator's signal.
- Symlinks: recorded with targets, never followed (metadata.py
  policy). A symlink pointing INTO the tree does not duplicate data;
  one pointing OUT does not smuggle external data in.

EXCLUDES
========
Caller-supplied predicate on relative paths (config-driven at the
CLI layer, decision 20). The scanner does not interpret patterns —
mechanism here, policy upstairs.
"""

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
    """Outcome of one scan. files/dirs/symlinks are counts of entries
    captured; skipped is (path, reason) — its emptiness is the 'clean
    backup' criterion."""
    files: int = 0
    dirs: int = 0
    symlinks: int = 0
    bytes_read: int = 0
    chunks_new: int = 0          # approximate: counts store misses
    skipped: list[tuple[str, str]] = field(default_factory=list)


ExcludeFn = Callable[[str], bool]      # relative path -> skip?


def _scan_file(store: ObjectStore, path: Path,
               report: ScanReport) -> tuple[tuple[bytes, ...], bytes]:
    """One pass: chunk ids + whole-file hash. See PIPELINE above."""
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


def scan_directory(store: ObjectStore, root: Path,
                   exclude: ExcludeFn | None = None,
                   _rel: str = "") -> tuple[bytes, ScanReport]:
    """Scan `root`, store everything, return (root_tree_id, report).

    Caller contract: store.flush() after this returns, BEFORE writing
    any snapshot record referencing the root id (snapshot.py enforces
    it). The root id is meaningless until the chunks behind it are
    durable.
    """
    report = ScanReport()
    root_id = _scan_dir_recursive(store, Path(root), exclude, _rel, report)
    return root_id, report


def _scan_dir_recursive(store: ObjectStore, dirpath: Path,
                        exclude: ExcludeFn | None, rel: str,
                        report: ScanReport) -> bytes:
    entries: list[TreeEntry] = []

    try:
        names = sorted(os.listdir(dirpath))          # determinism
    except OSError as exc:
        # Unreadable directory: represented as empty rather than
        # aborting the whole backup; the skip record carries truth.
        report.skipped.append((rel or ".", f"unreadable dir: {exc}"))
        names = []

    for name in names:
        child = dirpath / name
        child_rel = f"{rel}{name}" if not rel else f"{rel}/{name}"

        if exclude is not None and exclude(child_rel):
            continue

        try:
            meta = FileMeta.from_path(child)
        except OSError as exc:                        # vanished / EACCES
            report.skipped.append((child_rel, f"lstat failed: {exc}"))
            continue

        if meta is None:
            report.skipped.append((child_rel, "special file (socket/fifo/device)"))
            continue

        try:
            if meta.type == TYPE_FILE:
                chunks, fhash = _scan_file(store, child, report)
                entries.append(TreeEntry(name=name, meta=meta,
                                         chunks=chunks, file_hash=fhash))
                report.files += 1
            elif meta.type == TYPE_DIR:
                tree_id = _scan_dir_recursive(store, child, exclude,
                                              child_rel, report)
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
