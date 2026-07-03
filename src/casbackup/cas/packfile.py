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

@dataclass(frozen=True)
class PackEntry:
    chunk_id: bytes
    offset: int          # byte offset of the sealed blob within the pack
    length: int          # length of the sealed blob


    def __init__(self, backend: Backend) -> None:
        self._backend = backend
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
    return backend.get_range(pack_name(pack_id), entry.offset, entry.length)


def iter_entries(backend: Backend,
                 pack_id: bytes) -> Iterator[tuple[PackEntry, int]]:
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
