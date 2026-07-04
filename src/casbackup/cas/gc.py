from __future__ import annotations

from dataclasses import dataclass, field

from . import hasher
from .backend.base import Backend, BlobNotFound
from .index import ChunkIndex
from .packfile import PACK_PREFIX, PackWriter, iter_entries, pack_name, read_blob

DEFAULT_REPACK_THRESHOLD: float = 0.20


@dataclass
class GCStats:
    """What a GC run did — surfaced by the prune command."""

    chunks_total: int = 0
    chunks_dead: int = 0
    packs_total: int = 0
    packs_deleted: int = 0
    packs_repacked: int = 0
    packs_kept: int = 0
    orphan_packs_deleted: int = 0
    bytes_reclaimed: int = 0
    notes: list[str] = field(default_factory=list)


def _list_backend_packs(backend: Backend) -> dict[bytes, str]:
    """pack_id -> blob name, for every pack blob physically present."""
    out: dict[bytes, str] = {}
    for name in backend.list(PACK_PREFIX):
        hex_part = name[len(PACK_PREFIX) :].removesuffix(".pack")
        try:
            out[hasher.from_hex(hex_part)] = name
        except ValueError:
            continue  # not a pack blob; leave foreign files alone
    return out


def collect(
    backend: Backend,
    index: ChunkIndex,
    live: set[bytes],
    repack_threshold: float = DEFAULT_REPACK_THRESHOLD,
) -> GCStats:
    stats = GCStats()

    packs: dict[bytes, tuple[list[bytes], list[bytes]]] = {}
    for cid, pack_id in index.iter_all():
        stats.chunks_total += 1
        bucket = packs.setdefault(pack_id, ([], []))
        if cid in live:
            bucket[0].append(cid)
        else:
            bucket[1].append(cid)
            stats.chunks_dead += 1

    stats.packs_total = len(packs)
    all_dead_ids: list[bytes] = []

    # ---- sweep, pack by pack ---------------------------------------------------
    for pack_id, (live_ids, dead_ids) in packs.items():
        name = pack_name(pack_id)

        if not dead_ids:  # fully live
            stats.packs_kept += 1
            continue

        all_dead_ids.extend(dead_ids)

        if not live_ids:  # fully dead
            stats.bytes_reclaimed += backend.size(name)
            backend.delete(name)  # step 3
            stats.packs_deleted += 1
            continue

        # mixed: repack only past the economic threshold
        dead_fraction = len(dead_ids) / (len(live_ids) + len(dead_ids))
        if dead_fraction < repack_threshold:
            stats.packs_kept += 1
            stats.notes.append(
                f"{name}: {dead_fraction:.0%} dead, below threshold "
                f"{repack_threshold:.0%} — deferred"
            )
            for cid in dead_ids:
                all_dead_ids.remove(cid)
            continue

        # --- repack: copy live sealed blobs verbatim (steps 1-2) ---
        writer = PackWriter(backend)
        moved = []
        for cid in live_ids:
            located = index.get(cid)
            assert located is not None
            _pid, entry = located
            sealed = read_blob(backend, pack_id, entry)
            moved.append(writer.add(cid, sealed))
        new_pack_id, entries = writer.finalize()  # step 1
        index.add_pack(new_pack_id, entries)  # step 2
        old_size = backend.size(name)
        backend.delete(name)  # step 3
        stats.bytes_reclaimed += old_size
        stats.packs_repacked += 1

    # ---- step 4: bookkeeping, strictly last -------------------------------------
    if all_dead_ids:
        index.remove(all_dead_ids)

    # ---- orphan packs: in backend, unknown to index ------------------------------
    indexed_packs = {pid for _cid, pid in index.iter_all()}
    for pack_id, name in _list_backend_packs(backend).items():
        if pack_id in indexed_packs:
            continue
        entries = [e for e, _ in iter_entries(backend, pack_id)]
        live_here = [e for e in entries if e.chunk_id in live]
        if live_here:
            index.add_pack(pack_id, entries)
            stats.notes.append(
                f"{name}: orphan pack held {len(live_here)} live "
                f"chunk(s) — adopted into index, not deleted"
            )
            continue
        try:
            stats.bytes_reclaimed += backend.size(name)
            backend.delete(name)
            stats.orphan_packs_deleted += 1
        except BlobNotFound:
            pass

    return stats
