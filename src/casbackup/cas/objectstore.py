"""Object store: the CAS engine's public API (decision 1's core).

WHAT THIS LAYER IS
==================
The composition point of everything below it. Callers (the backup
client, later any other client) speak three verbs:

    put(data)       -> chunk_id     store bytes, dedup-aware
    get(chunk_id)   -> bytes        retrieve, integrity-verified
    has(chunk_id)   -> bool         existence probe

No files, no paths, no snapshots — those concepts belong to backup/.
This layer knows only chunks. That boundary IS decision 1: anything
that can express itself as "store these byte sequences, give me their
ids" can be a client of this engine.

THE WRITE PIPELINE (put)
========================
    data
      -> hasher.chunk_id(data)            identity from PLAINTEXT
      -> index.has(id)? ---- yes --> return id        (dedup: zero I/O)
      -> compress.compress(data)          zstd-or-stored framing
      -> crypto.encrypt(key, ., aad=id)   sealed, id-bound
      -> PackWriter.add(id, sealed)       staged into current pack
      -> [pack reaches target size] finalize -> backend -> index.add_pack
      -> return id

Two orderings enforce two guarantees:
- Hash BEFORE compress/encrypt: ids are stable across compression
  versions and encryption randomness (hasher.py rationale).
- Backend put BEFORE index insert: the crash-safety ordering
  (packfile.py rationale) — the index never references data that
  is not durably stored.

PENDING WRITES AND flush()
==========================
Chunks accumulate in an open PackWriter until DEFAULT_PACK_SIZE, so a
just-put() chunk may exist only in staging: not yet in the backend,
not yet in the index. Consequences callers must respect:

- get()/has() consult a small in-memory table of pending entries so
  the engine is read-your-writes consistent within a session.
- flush() finalizes the open pack. The backup client calls it BEFORE
  writing any manifest that references the flushed chunks — the same
  ordering discipline again, one level up.
- close() flushes implicitly. A crash before flush loses only staged
  chunks; the source data still exists (it is a backup tool — the
  source is the source of truth until a snapshot completes).

THE READ PIPELINE (get)
=======================
    index.get(id) -> (pack, offset, length)
    backend.get_range(...)                        ranged read
    crypto.decrypt(key, sealed, aad=id)           AEAD verify + open
    compress.decompress(...)
    hasher.chunk_id(plaintext) == id?  else CorruptChunk

Decision 17's verify-on-read is those last two checks: the AEAD tag
catches storage tampering/corruption; the final re-hash catches
everything else end-to-end (including bugs in this very pipeline).
Every restored byte passes both. `check` (verify.py) reuses get() for
exactly this reason.
"""

from __future__ import annotations

from typing import Iterator

from . import compress, crypto, hasher
from .backend.base import Backend, BackendError, BlobNotFound
from .index import ChunkIndex
from .packfile import (DEFAULT_PACK_SIZE, PackEntry, PackWriter, read_blob)


class ObjectStoreError(Exception):
    """Base for object-store failures."""


class ChunkNotFound(ObjectStoreError):
    """get() for an id absent from index and pending writes."""


class CorruptChunk(ObjectStoreError):
    """Retrieved data failed verification. Distinguishes WHICH layer
    caught it (message) — AEAD failure vs plaintext hash mismatch —
    because they implicate different failure locations: the former is
    storage-side damage/tampering, the latter suggests damage predating
    encryption or a pipeline bug."""


class ObjectStore:
    """See module docstring. One instance per open repository session.

    Args:
        backend:   blob storage (any Backend implementation).
        index:     the local chunk index.
        key:       32-byte repository master key (crypto.py).
        pack_size: staging threshold before a pack is flushed.
    """

    def __init__(self, backend: Backend, index: ChunkIndex, key: bytes,
                 pack_size: int = DEFAULT_PACK_SIZE) -> None:
        self._backend = backend
        self._index = index
        self._key = key
        self._pack_size = pack_size
        self._writer: PackWriter | None = None
        # Read-your-writes table: chunk_id -> sealed blob, for chunks
        # staged in the open pack. Bounded by pack_size (~64 MiB of
        # sealed data) — acceptable single-session memory ceiling.
        self._pending: dict[bytes, bytes] = {}

    # -- write path ----------------------------------------------------------

    def put(self, data: bytes) -> bytes:
        """Store one chunk. Returns its id. Idempotent by construction:
        a duplicate chunk costs one hash + one index probe, no I/O."""
        cid = hasher.chunk_id(data)

        if cid in self._pending or self._index.has(cid):
            return cid                                    # dedup hit

        sealed = crypto.encrypt(self._key, compress.compress(data), aad=cid)

        if self._writer is None:
            self._writer = PackWriter(self._backend)
        self._writer.add(cid, sealed)
        self._pending[cid] = sealed

        if self._writer.size >= self._pack_size:
            self.flush()
        return cid

    def flush(self) -> None:
        """Finalize the open pack: backend put, THEN index insert,
        then clear pending. Callers writing references to stored
        chunks (manifests) MUST flush first."""
        if self._writer is None:
            return
        writer, self._writer = self._writer, None
        pack_id, entries = writer.finalize()
        self._index.add_pack(pack_id, entries)            # ordering!
        self._pending.clear()

    # -- read path -----------------------------------------------------------

    def has(self, cid: bytes) -> bool:
        return cid in self._pending or self._index.has(cid)

    def get(self, cid: bytes) -> bytes:
        """Retrieve one chunk, fully verified (module docstring)."""
        sealed = self._pending.get(cid)
        if sealed is None:
            located = self._index.get(cid)
            if located is None:
                raise ChunkNotFound(hasher.to_hex(cid))
            pack_id, entry = located
            try:
                sealed = read_blob(self._backend, pack_id, entry)
            except BlobNotFound:
                raise ChunkNotFound(
                    f"{hasher.to_hex(cid)}: indexed in pack "
                    f"{hasher.to_hex(pack_id)} but the pack is missing "
                    f"from the backend") from None
            except BackendError as exc:
                raise CorruptChunk(
                    f"{hasher.to_hex(cid)}: backend read failed "
                    f"({exc})") from exc

        try:
            framed = crypto.decrypt(self._key, sealed, aad=cid)
        except crypto.DecryptionError as exc:
            raise CorruptChunk(
                f"{hasher.to_hex(cid)}: AEAD authentication failed "
                f"(storage corruption or tampering)") from exc

        data = compress.decompress(framed)

        if hasher.chunk_id(data) != cid:
            raise CorruptChunk(
                f"{hasher.to_hex(cid)}: plaintext hash mismatch "
                f"(pre-encryption damage or pipeline bug)")
        return data

    # -- iteration (GC / check support) ---------------------------------------

    def iter_chunk_ids(self) -> Iterator[bytes]:
        """Every chunk id the index knows. GC's universe enumeration."""
        for cid, _pack in self._index.iter_all():
            yield cid

    # -- lifecycle -------------------------------------------------------------

    def close(self) -> None:
        self.flush()

    def __enter__(self) -> "ObjectStore":
        return self

    def __exit__(self, *exc) -> None:
        # Deliberate: flush on clean exit only. On an exception mid-
        # backup, staged chunks are abandoned (writer temp file dies
        # with the process); flushing a half-written state would be
        # harmless (orphans) but pointless work during error handling.
        if exc == (None, None, None):
            self.close()
        elif self._writer is not None:
            self._writer.abort()
            self._writer = None
            self._pending.clear()
