from __future__ import annotations

import random
from dataclasses import dataclass
from tkinter.constants import TRUE
from typing import BinaryIO, Iterator

MIN_SIZE = 16 * 1024
AVG_SIZE = 64 * 1024
MAX_SIZE = 256 * 1024
MASK_HARD: int = 0x0000_D900_0353_1344  # 18 one-bits — while size < AVG
MASK_EASY: int = 0x0000_D900_0303_0000  # 14 one-bits — while size >= AVG

_MASK64 = 0xFFFF_FFFF_FFFF_FFFF

_GEAR_SEED = 0x2F87_31C9_A5B6_40DE


def build_gear_table(seed: int) -> tuple[int, ...]:
    rng = random.Random(seed)
    return tuple(rng.getrandbits(64) for _ in range(256))


GEAR: tuple[int, ...] = build_gear_table(_GEAR_SEED)


@dataclass(frozen=True)
class Chunk:
    offset: int
    data: bytes

    def __len__(self) -> int:
        return len(self.data)


def find_cut(data: bytes, start: int, end: int) -> int:
    length = end - start
    if length <= MIN_SIZE:
        return end
    fp = 0
    gear = GEAR
    switch = start + min(AVG_SIZE, length)
    limit = start + length
    i = start + MIN_SIZE
    while i < switch:
        fp = ((fp << 1) + gear[data[i]]) & _MASK64
        if fp & MASK_HARD == 0:
            return i + 1
        i += 1
    while i < limit:
        fp = ((fp << 1) + gear[data[i]]) & _MASK64
        if fp & MASK_EASY == 0:
            return i + 1
        i += 1

    return limit


_READ_SIZE = 4 * MAX_SIZE


def chunk_stream(stream: BinaryIO) -> Iterator[Chunk]:
    buf = bytearray()
    offset = 0
    eof = False
    while True:
        while not eof and len(buf) < MAX_SIZE:
            block = stream.read(_READ_SIZE)
            if not block:
                eof = True
            else:
                buf.extend(block)
        if not buf:
            return
        end = min(len(buf), MAX_SIZE)
        window = bytes(buf[:end])
        cut = find_cut(window, 0, end)
        yield Chunk(offset=offset, data=window[:cut])
        del buf[:cut]
        offset += cut


def chunk_bytes(data: bytes) -> list[Chunk]:
    import io

    return list(chunk_stream(io.BytesIO(data)))
