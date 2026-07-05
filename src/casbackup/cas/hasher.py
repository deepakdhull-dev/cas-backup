"""Chunk identity hashing for the CAS engine.

WHY THIS FILE EXISTS
====================
In a content-addressable store, a chunk's *name* is derived from its
*content*. Two chunks with identical bytes always get the same name, so
the store keeps only one copy — that is the entire deduplication
mechanism. The function that turns bytes into a name must therefore be:

1. Deterministic — same input, same output, always, on every machine.
2. Collision-resistant — it must be computationally infeasible for two
   *different* byte sequences to produce the same name. If a collision
   were possible, the store would silently return the wrong chunk's data
   during restore, corrupting files with no error raised. This is why a
   *cryptographic* hash is mandatory here; a fast non-cryptographic hash
   (xxHash, CRC32) is not safe as the sole identity.
3. Fixed-size output — names must be uniform so the index and pack
   format can treat them as fixed-width keys.

DECISION (locked): SHA-256.
- 32-byte (256-bit) digest. Collision resistance ~2^128 operations —
  far beyond feasibility.
- Available in Python's stdlib (`hashlib`), no external dependency.
- Hardware-accelerated (SHA-NI instructions) on modern x86 CPUs via
  OpenSSL, which hashlib uses under the hood.

TERMINOLOGY USED ACROSS THE CODEBASE
- "digest"    : the raw 32 bytes returned by SHA-256.
- "chunk id"  : that digest, used as the chunk's identity/key.
- "hex id"    : the 64-character lowercase hex encoding of the digest,
                used only where humans read it (CLI output, manifests
                serialized as text). Internally we pass raw bytes —
                half the size, no encode/decode cost in hot paths.

RELATION TO THE CHUNKER'S ROLLING HASH
This is NOT the same hash the chunker uses. FastCDC uses a cheap
"gear" rolling hash purely to decide WHERE to cut chunk boundaries.
That hash never names anything and needs no collision resistance.
SHA-256 here names the chunk AFTER it has been cut. Two hashes, two
completely different jobs. Conflating them is a common design error.
"""

from __future__ import annotations

import hashlib

# Length of a raw SHA-256 digest in bytes. Other modules (index,
# packfile) import this constant to size their fixed-width key fields
# instead of hardcoding 32, so the hash algorithm could be swapped by
# changing only this module.
DIGEST_SIZE: int = hashlib.sha256().digest_size  # == 32


def chunk_id(data: bytes) -> bytes:
    """Compute the identity of a chunk from its raw (uncompressed,
    unencrypted) content.

    IMPORTANT ORDERING RULE: identity is always computed on the
    *plaintext* chunk, BEFORE compression and encryption. Reasons:

    - Compression output can differ between zstd versions/levels, so
      hashing compressed bytes would break dedup across environments.
    - Encryption output differs on every write (random nonce), so
      hashing ciphertext would make dedup impossible entirely.
    - Hashing plaintext lets restore verify end-to-end integrity: after
      decrypt + decompress, re-hash and compare to the id. Any
      corruption anywhere in the storage pipeline is caught.

    Args:
        data: full chunk content as bytes.

    Returns:
        32-byte raw digest (the chunk id).
    """
    return hashlib.sha256(data).digest()


def to_hex(cid: bytes) -> str:
    """Render a chunk id for human consumption (CLI, logs, manifests).

    64 lowercase hex chars, e.g. '3f18a9...'. Purely presentational.
    """
    return cid.hex()


def from_hex(hex_id: str) -> bytes:
    """Parse a hex chunk id back to raw bytes.

    Validates length so malformed manifest entries fail loudly here
    instead of producing silent lookup misses deeper in the stack.

    Raises:
        ValueError: if the string is not exactly 64 hex characters.
    """
    cid = bytes.fromhex(hex_id)
    if len(cid) != DIGEST_SIZE:
        raise ValueError(
            f"chunk id must be {DIGEST_SIZE} bytes ({DIGEST_SIZE * 2} hex "
            f"chars), got {len(cid)} bytes"
        )
    return cid


class StreamingHasher:
    """Incremental SHA-256 for data too large to hold in memory at once.

    The chunker emits whole chunks (max 256 KiB with our parameters),
    so chunk identity uses the one-shot `chunk_id()` above. This class
    exists for the OTHER hashing jobs in the system:

    - Whole-file hashes stored in manifests (lets `check` verify a
      restored file without re-reading chunk lists).
    - Pack file trailer checksums.

    Both involve data far larger than memory should hold, so bytes are
    fed in pieces:

        h = StreamingHasher()
        for block in read_blocks(f):
            h.update(block)
        digest = h.digest()

    Wrapping hashlib (rather than using it directly at call sites)
    keeps the "we use SHA-256" decision confined to this one file.
    """

    def __init__(self) -> None:
        self._h = hashlib.sha256()

    def update(self, data: bytes) -> None:
        """Feed the next piece of data. Order matters; pieces are
        logically concatenated."""
        self._h.update(data)

    def digest(self) -> bytes:
        """Finalize and return the 32-byte digest. The hasher may be
        queried multiple times; hashlib copies state internally."""
        return self._h.digest()

    def hexdigest(self) -> str:
        return self._h.hexdigest()
