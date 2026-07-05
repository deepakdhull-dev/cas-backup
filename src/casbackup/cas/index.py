"""Chunk location index (decision 7: LMDB).

ROLE
====
Answers, millions of times per backup run:

    have_i_seen(chunk_id)  -> bool          (the dedup test)
    where_is(chunk_id)     -> pack, offset, length   (the restore lookup)

It is a persistent map:

    key   : chunk_id            (32 bytes, raw)
    value : pack_id || offset || length     (32 + 8 + 4 = 44 bytes)

DERIVED DATA, NOT AUTHORITATIVE — the single most important design
fact about this file. Packs are self-describing (packfile.py per-entry
headers); the index is rebuildable from a pack scan (rebuild()).
Therefore:

- The index lives LOCALLY (never through the Backend), because LMDB
  requires an mmap-able local file — and may, because losing it loses
  nothing authoritative.
- Index corruption is an inconvenience (rebuild), never data loss.
- Crash-ordering rule from packfile.py: entries enter the index only
  AFTER their pack is durably in the backend. The failure mode is a
  missing index entry for an existing pack (worst case: a chunk is
  stored twice — wasted space, reconciled by rebuild), never an index
  entry for a missing pack (which would corrupt restores).

WHY LMDB FITS
=============
- B+tree in a memory-mapped file: reads are pointer walks through
  page cache, no syscall, no server process, no SQL layer. Point
  lookups on 32-byte keys — precisely our access pattern — are its
  best case.
- Single-writer/multi-reader with MVCC; writers never block readers.
  Under decision 12 (single-threaded) we use a fraction of this, but
  it costs nothing.
- ACID transactions: a batch of put()s commits atomically; a crash
  mid-commit leaves the previous consistent state.
- Contrast: SQLite carries SQL parsing/planning overhead per lookup
  (works, slower, more moving parts); RocksDB is write-optimized
  (LSM) with compaction background machinery — overkill; a plain dict
  flushed to disk loses crash atomicity and must fully load at open.

MAP SIZE — LMDB'S ONE OPERATIONAL SHARP EDGE
============================================
LMDB mmaps a fixed maximum size ("map size") at open; writing past it
raises MapFullError. The file on disk is sparse — map size reserves
address space, not disk. Default here: 4 GiB ≈ 90 M chunk entries ≈
5+ TiB of unique data at 64 KiB chunks; generous and free. Tunable via
config (decision 20). On MapFullError, close and reopen with a larger
size; v1 surfaces the error with that instruction rather than
auto-resizing (silent auto-grow hides misconfiguration).

TRANSACTION DISCIPLINE
======================
One LMDB write txn per pack finalize (a batch of ~1000 puts), not per
chunk: commit cost (fsync) amortizes exactly like packs amortize blob
writes. Reads use ambient read txns per call — cheap in LMDB (a
snapshot pointer, no locks).
"""

from __future__ import annotations

import struct
from pathlib import Path
from typing import Iterable, Iterator

import lmdb

from . import hasher
from .packfile import PackEntry

_VALUE = struct.Struct(">32sQI")            # pack_id, offset u64, length u32
VALUE_SIZE: int = _VALUE.size               # 44 bytes

DEFAULT_MAP_SIZE: int = 4 * 1024 * 1024 * 1024   # 4 GiB address space


class IndexError_(Exception):
    """Index-layer failure. Named with trailing underscore to avoid
    shadowing the builtin IndexError (a sequence-subscript error,
    unrelated); callers import it explicitly so ambiguity never
    arises in code."""


class ChunkIndex:
    """Persistent chunk_id -> (pack_id, offset, length) map.

    Lifecycle: open once per repository session, close() on exit (the
    context-manager protocol is provided). All methods valid between.
    """

    def __init__(self, path: str | Path,
                 map_size: int = DEFAULT_MAP_SIZE) -> None:
        # subdir=True: LMDB manages a directory (data.mdb + lock.mdb).
        # sync=True (default): commits fsync — crash durability, the
        # point of using a real storage engine. metasync default True.
        self._env = lmdb.open(str(path), map_size=map_size,
                              subdir=True, max_dbs=0)

    # -- writes ------------------------------------------------------------

    def add_pack(self, pack_id: bytes,
                 entries: Iterable[PackEntry]) -> None:
        """Index every entry of one finalized pack, atomically.

        Called by objectstore.py strictly AFTER PackWriter.finalize()
        returned (see crash-ordering rule, module docstring). All
        entries commit in one txn: after a crash the pack is either
        fully indexed or not at all — never half.

        Duplicate chunk_ids (same chunk in two packs, possible after a
        crash-then-rerun) OVERWRITE: last pack wins. Both copies hold
        identical plaintext; either is valid; GC eventually reclaims
        the unreferenced one.
        """
        try:
            with self._env.begin(write=True) as txn:
                for e in entries:
                    txn.put(e.chunk_id,
                            _VALUE.pack(pack_id, e.offset, e.length))
        except lmdb.MapFullError as exc:
            raise IndexError_(
                "chunk index map size exhausted — raise index.map_size "
                "in the repository config and reopen"
            ) from exc

    # -- reads -------------------------------------------------------------

    def has(self, chunk_id: bytes) -> bool:
        """The dedup test. Hot path: called once per chunk of every
        file of every backup run."""
        with self._env.begin() as txn:
            return txn.get(chunk_id) is not None

    def get(self, chunk_id: bytes) -> tuple[bytes, PackEntry] | None:
        """Locate a chunk. Returns (pack_id, entry) or None."""
        with self._env.begin() as txn:
            raw = txn.get(chunk_id)
        if raw is None:
            return None
        pack_id, offset, length = _VALUE.unpack(raw)
        return pack_id, PackEntry(chunk_id=bytes(chunk_id),
                                  offset=offset, length=length)

    def __len__(self) -> int:
        with self._env.begin() as txn:
            return txn.stat()["entries"]

    def iter_all(self) -> Iterator[tuple[bytes, bytes]]:
        """Yield (chunk_id, pack_id) for every indexed chunk.

        GC's sweep phase (decision 13) consumes this to enumerate the
        chunk universe; `check` uses it to cross-verify against pack
        scans. Streams via LMDB cursor — no full materialization.
        """
        with self._env.begin() as txn:
            for key, raw in txn.cursor():
                pack_id = _VALUE.unpack(raw)[0]
                yield bytes(key), pack_id

    # -- maintenance ---------------------------------------------------------

    def remove(self, chunk_ids: Iterable[bytes]) -> None:
        """Drop entries (GC sweep after repack). One atomic txn."""
        with self._env.begin(write=True) as txn:
            for cid in chunk_ids:
                txn.delete(cid)

    def clear(self) -> None:
        """Empty the index. First step of rebuild()."""
        with self._env.begin(write=True) as txn:
            db = self._env.open_db(txn=txn)
            txn.drop(db, delete=False)

    def rebuild(self, backend, pack_ids: Iterable[bytes]) -> int:
        """Reconstruct the entire index from pack scans.

        The repair path proving the index is derived data: clear, then
        iter_entries() over every pack (headers only — cheap), re-add.
        Returns entries indexed. Invoked by `check --rebuild-index`
        (verify.py stage).
        """
        from .packfile import iter_entries   # local import: avoid cycle
        self.clear()
        count = 0
        for pack_id in pack_ids:
            entries = [e for e, _ in iter_entries(backend, pack_id)]
            self.add_pack(pack_id, entries)
            count += len(entries)
        return count

    # -- lifecycle -----------------------------------------------------------

    def close(self) -> None:
        self._env.close()

    def __enter__(self) -> "ChunkIndex":
        return self

    def __exit__(self, *exc) -> None:
        self.close()


def _selfcheck() -> None:
    """Module invariant: value struct matches hasher digest size."""
    assert VALUE_SIZE == hasher.DIGEST_SIZE + 8 + 4


_selfcheck()
