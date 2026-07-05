"""Per-chunk compression (decision 10: zstd, level 3).

WHERE COMPRESSION SITS IN THE PIPELINE
======================================
    raw chunk --(SHA-256 identity)--> compress --> encrypt --> store

The order is fixed and each ordering constraint has a reason:

1. IDENTITY BEFORE COMPRESSION. The chunk id names the *plaintext*
   bytes (see hasher.py). Compressed output may vary across zstd
   versions; ids must not.

2. COMPRESSION BEFORE ENCRYPTION — this direction is mandatory, not a
   preference. Good encryption output is indistinguishable from random
   noise, and random noise is incompressible (compression works by
   finding patterns; encryption's job is to destroy every pattern).
   Compress-after-encrypt achieves ~0% reduction. Encrypt-after-
   compress works fine.

WHY PER-CHUNK, NOT PER-FILE
===========================
Chunks are the unit of storage and dedup. If we compressed whole files
before chunking, chunk boundaries would land in compressed bytes, and
a 1-byte plaintext edit changes the entire compressed stream after
that point (compressors carry state forward) — CDC's resync property
would be destroyed. Compressing each chunk independently keeps chunks
independently retrievable: restore of one file touches only that
file's chunks, each decompressed in isolation.

The cost: compression ratio suffers slightly versus whole-file
compression, because zstd cannot exploit redundancy that spans chunk
boundaries and each 64 KiB chunk pays its own header/warm-up overhead.
At 64 KiB average this cost is small; it is the standard tradeoff every
dedup system (restic, borg) accepts.

WHY ZSTD LEVEL 3
================
- zstd dominates the speed/ratio frontier for this use case: gzip is
  slower AND compresses worse; LZ4 is faster but with meaningfully
  worse ratio; xz compresses better but is an order of magnitude
  slower — unacceptable in a backup hot path.
- Level 3 is zstd's own default: near-top throughput while capturing
  most of the achievable ratio. Higher levels trade a lot of CPU for
  a little ratio; sensible for archival, not for every-backup-run.

INCOMPRESSIBLE DATA HANDLING
============================
Much real data is already compressed (jpg, mp4, zip, encrypted blobs).
Running zstd over it wastes CPU and — worse — zstd output on
incompressible input is slightly LARGER than the input (framing
overhead). We handle this with a stored-vs-compressed flag: if
compression doesn't shrink the chunk, store it raw and record which
form was used. One byte of framing per chunk buys us the best of both.

FRAMING FORMAT (this module's on-disk contract)
===============================================
    output = 1-byte tag || payload

    tag 0x00 = payload is the raw chunk, stored uncompressed
    tag 0x01 = payload is a zstd frame of the chunk

The tag byte is covered by encryption (crypto.py encrypts this
module's output), so it is also integrity-protected by the AEAD tag.
Any new tag values (future algorithms) require a format version bump
(decision 21, formatver.py).
"""

from __future__ import annotations

import zstandard

# Compression level (decision 10). Format-relevant only in that lower
# levels still decompress fine — the level is NOT part of the on-disk
# contract; any zstd decompressor reads any level's frames.
ZSTD_LEVEL: int = 3

# Framing tags (ARE part of the on-disk contract).
TAG_STORED: int = 0x00
TAG_ZSTD: int = 0x01

# Module-level compressor/decompressor objects: constructing them has
# real cost (allocates internal zstd contexts); reuse across chunks.
# NOTE: zstandard's ZstdCompressor is not thread-safe for concurrent
# compress() calls. Irrelevant under decision 12 (single-threaded),
# but this line is where that assumption lives — flagged for the day
# the concurrency decision is revisited.
_compressor = zstandard.ZstdCompressor(level=ZSTD_LEVEL)
_decompressor = zstandard.ZstdDecompressor()


def compress(data: bytes) -> bytes:
    """Compress one chunk, with the stored-vs-compressed fallback.

    Returns tag byte + payload. Output is only ever 1 byte larger than
    the input in the worst case (incompressible chunk -> stored raw).
    """
    compressed = _compressor.compress(data)
    if len(compressed) < len(data):
        return bytes([TAG_ZSTD]) + compressed
    # Compression did not help (already-compressed/random data):
    # store raw. len(output) == len(input) + 1.
    return bytes([TAG_STORED]) + data


def decompress(blob: bytes) -> bytes:
    """Reverse `compress`. Input is tag byte + payload.

    Raises:
        ValueError: empty input or unknown tag. Unknown tags most
            likely mean a newer repository format read by older code —
            the error message says so to make that failure diagnosable.
        zstandard.ZstdError: corrupt zstd frame. In practice corruption
            is caught earlier by the AEAD auth tag (crypto.py) or later
            by chunk-id verification; this is defense in depth.
    """
    if not blob:
        raise ValueError("cannot decompress empty blob")

    tag = blob[0]
    payload = blob[1:]

    if tag == TAG_STORED:
        return bytes(payload)
    if tag == TAG_ZSTD:
        return _decompressor.decompress(payload)

    raise ValueError(
        f"unknown compression tag 0x{tag:02x} — repository may have been "
        f"written by a newer format version (see docs/format-spec.md)"
    )
