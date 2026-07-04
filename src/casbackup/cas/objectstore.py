
from __future__ import annotations

from typing import Iterator

from . import compress, crypto, hasher
from .backend.base import Backend
from .index import ChunkIndex
from .packfile import (DEFAULT_PACK_SIZE, PackEntry, PackWriter, read_blob)

class ObjectStoreError(Exception):


class ChunkNotFound(ObjectStoreError):


class CorruptChunk(ObjectStoreError):


class ObjectStore:

    def __init__(self, backend: Backend, index: ChunkIndex, key: bytes,
                 pack_size: int = DEFAULT_PACK_SIZE) -> None:
        self._backend = backend
        self._index = index
        self._key = key
        self._pack_size = pack_size
        self._writer: PackWriter | None = None
        self._pending: dict[bytes, bytes] = {}


    def put(self, data: bytes) -> bytes:
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
        if self._writer is None:
            return
        writer, self._writer = self._writer, None
        pack_id, entries = writer.finalize()
        self._index.add_pack(pack_id, entries)            # ordering!
        self._pending.clear()


    def has(self, cid: bytes) -> bool:
        return cid in self._pending or self._index.has(cid)

    def get(self, cid: bytes) -> bytes:
        sealed = self._pending.get(cid)
        if sealed is None:
            located = self._index.get(cid)
            if located is None:
                raise ChunkNotFound(hasher.to_hex(cid))
            pack_id, entry = located
            sealed = read_blob(self._backend, pack_id, entry)

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


    def iter_chunk_ids(self) -> Iterator[bytes]:
        """Every chunk id the index knows. GC's universe enumeration."""
        for cid, _pack in self._index.iter_all():
            yield cid


    def close(self) -> None:
        self.flush()

    def __enter__(self) -> "ObjectStore":
        return self

    def __exit__(self, *exc) -> None:
        if exc == (None, None, None):
            self.close()
        elif self._writer is not None:
            self._writer.abort()
            self._writer = None
            self._pending.clear()
