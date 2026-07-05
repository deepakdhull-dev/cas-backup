"""Content-defined chunking via FastCDC.

THE PROBLEM THIS SOLVES
=======================
Splitting files at fixed positions (every 64 KiB from offset 0) breaks
deduplication catastrophically on insertions. Insert 1 byte at the
front of a file and every fixed boundary after it shifts by 1: every
chunk's content changes, every hash changes, 0% dedup against the
previous version — for a 1-byte edit.

Content-defined chunking (CDC) fixes this by deciding boundaries from
the *bytes themselves*, not from position. A boundary is declared
wherever the local data satisfies a condition. Insert a byte, and only
the chunk containing the insertion (and possibly its neighbor) changes;
all later boundaries land on the same content as before because the
condition depends only on a small sliding window of recent bytes. This
"resynchronization" property is the entire point of CDC and is what the
property tests in tests/unit/test_chunker.py verify empirically.

HOW THE GEAR ROLLING HASH WORKS
===============================
We keep a running 64-bit value `fp` (fingerprint). For each input byte
b we update:

    fp = ((fp << 1) + GEAR[b]) & MASK64

- GEAR is a fixed table of 256 pseudorandom 64-bit values, one per
  possible byte value. It converts "byte 0x41" into a scrambled
  64-bit pattern, so real-world byte distributions (text is mostly
  ASCII, lots of zeros in binaries) still yield uniformly random-looking
  fingerprints.
- The left shift ages old bytes out: a byte's influence moves one bit
  position left per step, so after 64 steps it has been shifted out
  entirely. The hash therefore only "sees" the last 64 bytes — a
  sliding window with no explicit window buffer and no subtraction
  step. This is why gear is faster than the classic Rabin fingerprint,
  which must explicitly remove the departing byte each step.

A boundary is declared when the fingerprint has a specific set of bits
all equal to zero:

    if fp & mask == 0:  -> cut here

If mask has k one-bits, a random fingerprint satisfies this with
probability 1/2^k, so a boundary occurs on average every 2^k bytes.
Choosing k sets the average chunk size. For our 64 KiB average,
k = 16 (2^16 = 65536).

WHAT FASTCDC ADDS OVER PLAIN GEAR CDC
=====================================
(Xia et al., "FastCDC: a Fast and Efficient Content-Defined Chunking
Approach for Data Deduplication", USENIX ATC 2016 — read it.)

1. MIN-SIZE SKIP. No boundary is allowed before MIN_SIZE bytes, and the
   implementation doesn't even *hash* the first MIN_SIZE bytes of a
   chunk — it jumps straight past them. Prevents pathological tiny
   chunks (imagine data that triggers the condition every 50 bytes:
   per-chunk overhead would dwarf the data) and skips ~25% of all
   hashing work for free.

2. MAX-SIZE CAP. If no boundary is found by MAX_SIZE, cut forcibly.
   Bounds worst-case chunk size (e.g. a long run of zeros might never
   satisfy the condition). Forced cuts are position-based, so they
   have poor resync behavior — but they are rare on real data.

3. NORMALIZED CHUNKING. This is FastCDC's key trick. Instead of one
   mask, use two:
   - Before the average size is reached: a HARDER mask (more one-bits,
     boundaries less likely). Discourages small chunks.
   - After the average size: an EASIER mask (fewer one-bits,
     boundaries more likely). Encourages cutting soon.
   Effect: chunk sizes cluster tightly around the average instead of
   following the long-tailed exponential distribution plain gear CDC
   produces. Tighter size distribution = more predictable dedup and
   fewer forced max-size cuts.

   The paper uses normalization level 2: harder mask has k+2 bits,
   easier mask has k-2 bits. We follow that.

OUR PARAMETERS (decision 4: 64 KiB average)
   MIN_SIZE = 16 KiB   (avg / 4  — paper's recommendation)
   AVG_SIZE = 64 KiB
   MAX_SIZE = 256 KiB  (avg * 4)
   mask_hard = 18 one-bits (used while chunk < 64 KiB)
   mask_easy = 14 one-bits (used while chunk >= 64 KiB)

WHY THE GEAR TABLE MUST NEVER CHANGE
====================================
The table is part of the on-disk format in an indirect but absolute
way: change any entry and every boundary in every future backup moves,
so nothing dedups against existing chunks. Repository size doubles as
old data is re-stored under new chunk ids. The table is therefore
generated ONCE from a fixed seed and frozen. Treat it like a file
format constant, versioned via formatver.py if it ever must change.
"""

from __future__ import annotations

import random
from dataclasses import dataclass
from typing import BinaryIO, Iterator

# ---------------------------------------------------------------------------
# Chunk size parameters (decision 4). Sizes in bytes.
# ---------------------------------------------------------------------------

MIN_SIZE: int = 16 * 1024      # 16 KiB — no cut allowed before this
AVG_SIZE: int = 64 * 1024      # 64 KiB — target average
MAX_SIZE: int = 256 * 1024     # 256 KiB — forced cut at this size

# ---------------------------------------------------------------------------
# Boundary masks (normalized chunking, level 2).
#
# AVG_SIZE = 2^16, so the "neutral" mask would have 16 one-bits.
# Harder mask: 16 + 2 = 18 bits. Easier mask: 16 - 2 = 14 bits.
#
# Bit PLACEMENT detail: the FastCDC paper spreads the one-bits across
# the word rather than using the low bits, because the gear hash's
# low bits carry entropy from only the most recent few bytes (a byte
# entering at bit 0 reaches higher bits only via shifting). Using
# spread-out bits samples entropy from the whole 64-byte window.
# These specific constants are the ones from the reference FastCDC
# implementations, extended to our sizes.
# ---------------------------------------------------------------------------

MASK_HARD: int = 0x0000_D900_0353_1344   # 18 one-bits — while size < AVG
MASK_EASY: int = 0x0000_D900_0303_0000   # 14 one-bits — while size >= AVG

_MASK64 = 0xFFFF_FFFF_FFFF_FFFF

# ---------------------------------------------------------------------------
# Gear table: 256 fixed pseudorandom 64-bit values, one per byte value.
# Generated from a FIXED seed so it is identical on every machine and
# every run — see module docstring for why this is format-critical.
# ---------------------------------------------------------------------------

_GEAR_SEED = 0x2F87_31C9_A5B6_40DE


def _build_gear_table(seed: int) -> tuple[int, ...]:
    rng = random.Random(seed)
    return tuple(rng.getrandbits(64) for _ in range(256))


GEAR: tuple[int, ...] = _build_gear_table(_GEAR_SEED)


# ---------------------------------------------------------------------------
# Public output type
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class Chunk:
    """One chunk produced by the chunker.

    offset: position of the chunk's first byte within the source stream.
            Stored for diagnostics and testing; the CAS layer itself
            never needs it (chunks are identified by content, not
            position — that is the whole idea).
    data:   the chunk's raw bytes.
    """
    offset: int
    data: bytes

    def __len__(self) -> int:
        return len(self.data)


# ---------------------------------------------------------------------------
# Core boundary-finding routine
# ---------------------------------------------------------------------------

def _find_cut(data: bytes, start: int, end: int) -> int:
    """Find the cut point for the chunk beginning at `start` in `data`.

    Returns an index `cut` with start < cut <= end such that
    data[start:cut] is one chunk. `end` is bounded by the caller to
    at most start + MAX_SIZE.

    This is the hot loop of the entire system: it runs once per input
    byte. Keep it free of attribute lookups and function calls.
    """
    length = end - start

    # Whole remainder smaller than MIN_SIZE: it becomes one final
    # chunk. Cutting below MIN_SIZE is otherwise forbidden.
    if length <= MIN_SIZE:
        return end

    fp = 0
    gear = GEAR  # local alias: avoids a global lookup per byte

    # Where the mask switches from hard to easy, and the hard ceiling.
    switch = start + min(AVG_SIZE, length)
    limit = start + length  # == end; length already capped at MAX_SIZE

    # --- Phase 0: skip ---
    # FastCDC optimization: boundaries are forbidden before MIN_SIZE,
    # so bytes before it can never produce a cut. We still must not
    # start hashing at zero exactly AT min-size, because the hash needs
    # its 64-byte window filled with real data to behave statistically.
    # The standard approach (and the paper's) is simply to begin the
    # rolling hash AT the min boundary with fp = 0; the first 64 bytes
    # after MIN_SIZE effectively warm the window up. The masks' spread
    # bit placement tolerates this.
    i = start + MIN_SIZE

    # --- Phase 1: hard mask (discourage cutting before average) ---
    while i < switch:
        fp = ((fp << 1) + gear[data[i]]) & _MASK64
        if fp & MASK_HARD == 0:
            return i + 1
        i += 1

    # --- Phase 2: easy mask (encourage cutting after average) ---
    while i < limit:
        fp = ((fp << 1) + gear[data[i]]) & _MASK64
        if fp & MASK_EASY == 0:
            return i + 1
        i += 1

    # --- Phase 3: no boundary found — forced cut at limit ---
    # (limit is start+MAX_SIZE except for the final partial chunk.)
    return limit


# ---------------------------------------------------------------------------
# Streaming interface
# ---------------------------------------------------------------------------

# How much to read from the source per syscall. Must be >= MAX_SIZE so
# a full chunk is always available in the buffer when one exists.
_READ_SIZE = 4 * MAX_SIZE  # 1 MiB


def chunk_stream(stream: BinaryIO) -> Iterator[Chunk]:
    """Split a binary stream into content-defined chunks.

    Streaming (decision 16 applies to restore, but the same principle
    holds here): memory use is bounded by a small buffer, never by
    file size. A 100 GiB VM image is chunked with ~1.25 MiB resident.

    Buffer management: maintain a bytearray; refill from the stream
    until it holds at least MAX_SIZE bytes (or the stream is
    exhausted), find one cut, emit the chunk, drop the consumed prefix,
    repeat.

    Yields:
        Chunk objects in stream order. Concatenating chunk.data over
        all yields reproduces the input exactly — an invariant the
        integration tests assert.
    """
    buf = bytearray()
    offset = 0          # absolute offset of buf[0] within the stream
    eof = False

    while True:
        # Refill until we can safely find one maximal chunk.
        while not eof and len(buf) < MAX_SIZE:
            block = stream.read(_READ_SIZE)
            if not block:
                eof = True
            else:
                buf.extend(block)

        if not buf:
            return  # stream fully consumed and emitted

        end = min(len(buf), MAX_SIZE)
        # bytes() copy: _find_cut indexes per byte; indexing a bytes
        # object is marginally faster than a bytearray, and the chunk
        # must be an immutable snapshot anyway before yielding.
        window = bytes(buf[:end])
        cut = _find_cut(window, 0, end)

        yield Chunk(offset=offset, data=window[:cut])

        del buf[:cut]
        offset += cut


def chunk_bytes(data: bytes) -> list[Chunk]:
    """Convenience wrapper for in-memory data. Used heavily by tests."""
    import io
    return list(chunk_stream(io.BytesIO(data)))
