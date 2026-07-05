"""Pack file format (decision 6: packed chunk storage).

WHY PACKS INSTEAD OF ONE FILE PER CHUNK
=======================================
A Git-style objects/ab/cd... layout stores each chunk as its own file.
At 64 KiB average chunk size, a 500 GiB repository holds ~8 million
chunks = 8 million files. Consequences:

- One inode per chunk. Filesystems allocate in blocks (typically 4
  KiB); metadata overhead and internal fragmentation multiply.
- Directory operations degrade: enumeration, backup-of-the-backup,
  rsync of the repo, fsck all crawl.
- Every chunk write is open+write+fsync+close+rename: four+ syscalls
  and a metadata journal commit for 64 KiB of payload. Throughput
  dies on syscall overhead, not bandwidth.
- Remote backends amplify this: 8 million S3 PUTs vs 8 thousand.

Packs amortize: append sealed chunks into a large buffer, flush as one
~64 MiB blob. 1000x fewer blobs, sequential writes, one fsync per pack.
Git itself packs for the same reason; restic uses packs; borg uses
segments (same idea).

PACK WIRE FORMAT (on-disk contract, versioned per decision 21)
==============================================================
    pack       := header entry*
    header     := magic "CBPK" (4 bytes) || format_version u8
    entry      := chunk_id (32 bytes, raw SHA-256)
               || blob_len u32 big-endian
               || blob (sealed bytes from crypto.py, exactly blob_len)

Design points, each load-bearing:

1. PER-ENTRY HEADERS make packs SELF-DESCRIBING. The LMDB index
   (index.py) is a derived local cache; if it is lost or corrupted, a
   linear scan of every pack rebuilds it completely (see iter_entries).
   Authoritative truth lives in packs; the index is an accelerator.
   This is the property that makes "delete the index and rebuild" a
   valid repair strategy for `check`.

2. chunk_id STORED IN THE CLEAR (not encrypted). Required for index
   rebuild without decryption... but is it a leak? The id is the
   SHA-256 of plaintext. An attacker holding the repo can test "does
   this repo contain THIS exact known chunk?" by hashing a guessed
   chunk. This is the confirmation-attack surface accepted when
   convergent encryption was REJECTED in decision 11 — ironic but
   true: storing plaintext hashes reintroduces a slice of it.
   Restic's answer: encrypt pack headers, keep a separate encrypted
   index format. Cost: index rebuild requires the key (acceptable) and
   a more complex pack trailer format. v1 accepts the confirmation
   surface for format simplicity; revisit under a format version bump.
   FLAGGED as a known, deliberate tradeoff — say this in interviews
   before the interviewer says it to you.

3. BIG-ENDIAN LENGTHS. Network byte order; conventional for formats.
   struct format ">32sI" reads/writes one entry header.

4. NO COMPRESSION/ENCRYPTION AT PACK LEVEL. Entries are already
   sealed blobs (compressed then encrypted per chunk). The pack is a
   dumb container; it can be copied, ranged into, and scanned without
   any key material except point 2's rebuild case.

PACK NAMING: <sha256-of-pack-content>.pack
==========================================
The pack's own bytes are hashed while staging; the hex digest names
the blob. Consequences:

- Packs are immutable by construction: content change => name change.
- `check` verifies whole-pack integrity by re-hashing and comparing
  to the name — no separate checksum field needed.
- Names never collide with meaning: two identical packs (impossible
  in practice, harmless in theory) would coincide into one blob.

WRITE PATH AND CRASH SAFETY
===========================
PackWriter appends entries to an anonymous local temp file (staging),
hashing incrementally. On finalize: fsync staging, then hand it to
backend.put_file under the final packs/<hex>.pack name (atomic per the
Backend contract). Only AFTER the backend put returns does the caller
insert the pack's entries into the index. Crash before the put: an
orphan temp file, cleaned on next open. Crash after put but before
index insert: an unreferenced pack — GC's mark phase never marks it,
sweep reclaims it. No crash window yields an index entry pointing at
missing data. Ordering IS the crash-safety mechanism; no journal
needed.

TARGET PACK SIZE
================
DEFAULT_PACK_SIZE = 64 MiB: large enough to amortize per-blob costs,
small enough that GC repacking (rewriting packs to drop dead chunks)
moves tolerable amounts of data per pack. Config-tunable (decision 20);
not format-relevant — readers handle any size.
"""

from __future__ import annotations

import os
import struct
import tempfile
from dataclasses import dataclass
from typing import Iterator

from . import hasher
from .backend.base import Backend

MAGIC: bytes = b"CBPK"
PACK_FORMAT_VERSION: int = 1
HEADER_SIZE: int = len(MAGIC) + 1                      # 5 bytes

_ENTRY_HDR = struct.Struct(">32sI")                    # chunk_id, blob_len
ENTRY_HDR_SIZE: int = _ENTRY_HDR.size                  # 36 bytes

DEFAULT_PACK_SIZE: int = 64 * 1024 * 1024              # 64 MiB target

PACK_PREFIX = "packs/"


class PackFormatError(Exception):
    """Pack fails structural validation: bad magic, unknown version,
    truncated entry, entry overrunning the file. Signals corruption or
    a newer writer; `check` reports it, restore treats it as fatal for
    the affected chunks."""


@dataclass(frozen=True)
class PackEntry:
    """Location of one sealed blob inside one pack.

    offset/length locate the BLOB (not the entry header): exactly the
    range a reader passes to backend.get_range. This tuple is what the
    index stores per chunk.
    """
    chunk_id: bytes
    offset: int          # byte offset of the sealed blob within the pack
    length: int          # length of the sealed blob


class PackWriter:
    """Accumulates sealed blobs into one pack; flushes atomically.

    Usage (driven by objectstore.py):

        w = PackWriter(backend)
        entries = []
        entries.append(w.add(cid, sealed))
        ...
        if w.size >= DEFAULT_PACK_SIZE:
            pack_id = w.finalize()      # -> now index the entries
            w = PackWriter(backend)

    Not reusable after finalize()/abort(). Single-threaded by decision
    12; no locking inside.
    """

    def __init__(self, backend: Backend) -> None:
        self._backend = backend
        # Unnamed temp file: vanishes automatically on process death —
        # crash cleanup for free. dir=None (system tmp) is fine because
        # backend.put_file streams content; same-filesystem rename
        # atomicity is the LOCAL BACKEND's concern, handled inside it.
        self._tmp = tempfile.TemporaryFile()
        self._hash = hasher.StreamingHasher()
        self._write(MAGIC + bytes([PACK_FORMAT_VERSION]))
        self._entries: list[PackEntry] = []
        self._finalized = False

    def _write(self, data: bytes) -> None:
        self._tmp.write(data)
        self._hash.update(data)

    @property
    def size(self) -> int:
        """Current staged size in bytes; caller's flush trigger."""
        return self._tmp.tell()

    @property
    def entry_count(self) -> int:
        return len(self._entries)

    def add(self, chunk_id: bytes, sealed_blob: bytes) -> PackEntry:
        """Append one sealed blob. Returns its location-to-be.

        The returned entry's offsets are valid only if finalize()
        later succeeds — callers must buffer entries and index them
        strictly after finalize() returns (crash-safety ordering, see
        module docstring).
        """
        if self._finalized:
            raise RuntimeError("PackWriter already finalized")
        if len(chunk_id) != hasher.DIGEST_SIZE:
            raise ValueError("bad chunk id length")

        self._write(_ENTRY_HDR.pack(chunk_id, len(sealed_blob)))
        offset = self._tmp.tell()          # blob starts after its header
        self._write(sealed_blob)

        entry = PackEntry(chunk_id=chunk_id, offset=offset,
                          length=len(sealed_blob))
        self._entries.append(entry)
        return entry

    def finalize(self) -> tuple[bytes, list[PackEntry]]:
        """Flush the pack to the backend. Returns (pack_id, entries).

        pack_id is the raw SHA-256 of the pack's full content; the
        blob name is packs/<hex(pack_id)>.pack.
        """
        if self._finalized:
            raise RuntimeError("PackWriter already finalized")
        if not self._entries:
            raise RuntimeError("refusing to write an empty pack")
        self._finalized = True

        self._tmp.flush()
        os.fsync(self._tmp.fileno())       # staged bytes durable pre-put

        pack_id = self._hash.digest()
        name = pack_name(pack_id)

        # TemporaryFile has no pathname portably; stream via a bounded
        # copy into backend.put_file's contract using a named temp.
        self._tmp.seek(0)
        with tempfile.NamedTemporaryFile(delete=False) as named:
            while True:
                block = self._tmp.read(1024 * 1024)
                if not block:
                    break
                named.write(block)
            named.flush()
            os.fsync(named.fileno())
            staged_path = named.name
        try:
            self._backend.put_file(name, staged_path)
        finally:
            os.unlink(staged_path)
        self._tmp.close()

        return pack_id, self._entries

    def abort(self) -> None:
        """Discard staged data. Safe to call anytime pre-finalize."""
        self._finalized = True
        self._tmp.close()


def pack_name(pack_id: bytes) -> str:
    return f"{PACK_PREFIX}{hasher.to_hex(pack_id)}.pack"


def read_blob(backend: Backend, pack_id: bytes, entry: PackEntry) -> bytes:
    """Fetch one sealed blob via ranged read — the restore hot path.

    Reads exactly entry.length bytes at entry.offset; never the whole
    pack. Integrity of the returned bytes is NOT checked here — the
    AEAD tag (crypto.decrypt) and the chunk-id re-hash upstack do that
    (decision 17's verify-on-read); duplicating it here would double
    hashing cost for nothing.
    """
    return backend.get_range(pack_name(pack_id), entry.offset, entry.length)


def iter_entries(backend: Backend,
                 pack_id: bytes) -> Iterator[tuple[PackEntry, int]]:
    """Scan a pack's entry headers WITHOUT reading blob bodies.

    Yields (entry, next_offset) pairs. This is the index-rebuild and
    `check` primitive (module docstring point 1): headers are hopped
    via ranged reads — for each entry read 36 bytes, skip blob_len,
    repeat. Cost per pack: entry_count small reads, zero blob I/O.

    Raises PackFormatError on any structural violation. A truncated
    final entry (crash artifact that atomic puts should make
    impossible) is reported, not silently tolerated: its presence
    means the backend's atomicity contract was violated — worth
    knowing loudly.
    """
    name = pack_name(pack_id)
    total = backend.size(name)

    header = backend.get_range(name, 0, HEADER_SIZE)
    if header[:4] != MAGIC:
        raise PackFormatError(f"{name}: bad magic {header[:4]!r}")
    version = header[4]
    if version != PACK_FORMAT_VERSION:
        raise PackFormatError(
            f"{name}: pack format v{version}, this build reads "
            f"v{PACK_FORMAT_VERSION} (see docs/format-spec.md)")

    pos = HEADER_SIZE
    while pos < total:
        if pos + ENTRY_HDR_SIZE > total:
            raise PackFormatError(f"{name}: truncated entry header at {pos}")
        raw = backend.get_range(name, pos, ENTRY_HDR_SIZE)
        chunk_id, blob_len = _ENTRY_HDR.unpack(raw)
        blob_off = pos + ENTRY_HDR_SIZE
        if blob_off + blob_len > total:
            raise PackFormatError(
                f"{name}: entry at {pos} overruns pack "
                f"({blob_off}+{blob_len} > {total})")
        yield PackEntry(chunk_id=chunk_id, offset=blob_off,
                        length=blob_len), blob_off + blob_len
        pos = blob_off + blob_len
