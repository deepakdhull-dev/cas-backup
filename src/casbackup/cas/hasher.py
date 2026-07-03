from __future__ import annotations

import hashlib

DIGEST_SIZE: int = hashlib.sha256().digest_size


def chunk_id(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def to_hex(cid: bytes) -> str:
    return cid.hex()


def from_hex(hex_id: str) -> bytes:
    cid = bytes.fromhex(hex_id)
    if len(cid) != DIGEST_SIZE:
        raise ValueError(
            f"chunk id must be {DIGEST_SIZE} bytes ({DIGEST_SIZE * 2} hex "
            f"chars), got {len(cid)} bytes"
        )
    return cid


class StreamingHasher:
    def __init__(self) -> None:
        self._h = hashlib.sha256()

    def update(self, data: bytes) -> None:
        self._h.update(data)

    def digest(self) -> bytes:
        return self._h.digest()

    def hexdigest(self) -> str:
        return self._h.hexdigest()
