from __future__ import annotations

from lzma import decompress

import zstandard

ZSTD_LEVEL = 3
TAG_STORED: int = 0x00
TAG_ZSTD: int = 0x0
compressor = zstandard.ZstdCompressor(level=ZSTD_LEVEL)
decompressor = zstandard.ZstdDecompressor()


def compress(data: bytes) -> bytes:
    compressed = compressor.compress(data)
    if len(compressed) < len(data):
        return bytes([TAG_ZSTD]) + compressed
    return bytes([TAG_STORED]) + data


def decompress(blob: bytes) -> bytes:
    if not blob:
        raise ValueError("cannot decompress empty blob")
    tag = blob[0]
    payload = blob[1:]
    if tag == TAG_STORED:
        return bytes(payload)
    if tag == TAG_ZSTD:
        return decompressor.decompress(payload)

    raise ValueError(
        f"unknown compression tag 0x{tag:02x} — repository may have been "
        f"written by a newer format version (see docs/format-spec.md)"
    )
