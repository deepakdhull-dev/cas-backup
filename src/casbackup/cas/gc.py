"""Garbage collection (decision 13: mark-and-sweep).

WHY GC EXISTS
=============
Deleting a snapshot deletes a manifest — a list of references. The
chunks it referenced remain in packs, possibly still referenced by
OTHER snapshots (cross-snapshot dedup, decision 18, guarantees heavy
sharing). A chunk is garbage only when NO live snapshot references it.
Computing that is a reachability problem over a DAG:

    snapshots -> manifests -> (tree nodes) -> chunk ids

WHY MARK-AND-SWEEP, NOT REFERENCE COUNTING (decision 13 rationale,
recorded where the code lives)
==================================================================
Refcounting stores a mutable counter per chunk, updated on every
snapshot create/delete. Counters drift: a crash between "delete
manifest" and "decrement its chunks" leaves counts permanently wrong,
and NOTHING detects the drift except a full recount — which is
mark-and-sweep. Mark-and-sweep skips the intermediary: it re-derives
liveness from the source of truth (live manifests) on every run.
Wrong is impossible, stale is impossible; cost is a full traversal
per GC run, amortized to irrelevance by running GC occasionally
(`prune`), not continuously. Git made the same call, same reasons.

LAYERING (decision 1 discipline)
================================
This module never reads manifests — manifests are a backup/ concept.
The caller (prune command) walks live manifests and hands this module
the LIVE SET of chunk ids. cas/gc.py owns everything below that line:
determining the dead set, reclaiming space, updating the index.
The engine stays client-agnostic; any future client supplies its own
roots the same way.

THE SWEEP PROBLEM UNDER PACKED STORAGE
======================================
Chunks live inside immutable packs (packfile.py). You cannot delete
one chunk from a pack; the unit of deletion is the whole pack. Sweep
therefore classifies packs:

    all chunks live          -> keep untouched
    all chunks dead          -> delete the pack blob outright
    mixed                    -> REPACK: copy the live sealed blobs
                                into a fresh pack, then delete the old

Repacking copies SEALED bytes verbatim — no decrypt/re-encrypt. Legal
because the AEAD binds ciphertext to the chunk id (AAD), not to any
pack location; a sealed blob is position-independent by construction.
GC therefore requires no key material and cannot corrupt plaintext
even if buggy: the worst a bad copy can do is fail AEAD on next read.

REPACK THRESHOLD
================
Repacking a pack that is 2% dead moves 98 units of data to reclaim 2.
Uneconomical. Mixed packs are repacked only when dead_fraction >=
threshold (default 0.20 — tunable via config, decision 20; the value
is a space/IO tradeoff knob with no correctness content). Below
threshold the dead bytes are tolerated as slack until enough
accumulates. Restic's prune has the same knob (--max-unused).

CRASH-SAFETY ORDERING (the part worth memorizing)
=================================================
    1. write new packs (backend put)         -- new copies durable
    2. index.add_pack(new locations)         -- reads now use copies
    3. delete old pack blobs                 -- originals gone
    4. index.remove(dead ids)                -- bookkeeping last

Crash after 1: orphan packs, unreferenced, next GC's pack-level scan
reclaims them. Crash after 2: duplicate storage of live chunks, index
points at the new copies, old packs unreferenced -> next GC deletes.
Crash after 3: dead index entries pointing at deleted packs — the one
genuinely bad intermediate state, healed by step 4 on the next run
because dead ids are recomputed from scratch; reads of dead ids were
already impossible via any live manifest (that is what dead MEANS).
No step can strand a live chunk: live data always exists in at least
one durably-written pack before any deletion touches its old home.

Pack-level orphan detection: packs present in the backend but absent
from the index (crash artifacts of interrupted backups — see
packfile.py) are deleted in the same sweep, after a safety re-scan
confirms none of their entries are live.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from . import hasher
from .backend.base import Backend, BlobNotFound
from .index import ChunkIndex
from .packfile import (PACK_PREFIX, PackWriter, iter_entries, pack_name,
                       read_blob)

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
        hex_part = name[len(PACK_PREFIX):].removesuffix(".pack")
        try:
            out[hasher.from_hex(hex_part)] = name
        except ValueError:
            continue  # not a pack blob; leave foreign files alone
    return out


def collect(backend: Backend, index: ChunkIndex, live: set[bytes],
            repack_threshold: float = DEFAULT_REPACK_THRESHOLD) -> GCStats:
    """Mark-and-sweep with repacking. `live` is the mark result,
    supplied by the caller (see LAYERING). Caller MUST hold the
    repository lock for the entire call — GC racing a writer is the
    scenario decision 15 exists to prevent.
    """
    stats = GCStats()

    # ---- classify every indexed chunk by pack --------------------------------
    # pack_id -> (live_ids, dead_ids) partition of that pack's chunks
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

        if not dead_ids:                                   # fully live
            stats.packs_kept += 1
            continue

        all_dead_ids.extend(dead_ids)

        if not live_ids:                                   # fully dead
            stats.bytes_reclaimed += backend.size(name)
            backend.delete(name)                           # step 3
            stats.packs_deleted += 1
            continue

        # mixed: repack only past the economic threshold
        dead_fraction = len(dead_ids) / (len(live_ids) + len(dead_ids))
        if dead_fraction < repack_threshold:
            stats.packs_kept += 1
            stats.notes.append(
                f"{name}: {dead_fraction:.0%} dead, below threshold "
                f"{repack_threshold:.0%} — deferred")
            # dead ids in a kept pack must ALSO stay in the index:
            # their storage still exists; removing the entries would
            # orphan retrievable bytes invisibly. Un-count them.
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
        new_pack_id, entries = writer.finalize()           # step 1
        index.add_pack(new_pack_id, entries)               # step 2
        old_size = backend.size(name)
        backend.delete(name)                               # step 3
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
        # Safety re-scan before deleting: an orphan pack could hold a
        # live chunk if the index lost entries (rebuild interrupted).
        # If any entry is live, adopt the pack into the index instead
        # of deleting data GC exists to protect.
        entries = [e for e, _ in iter_entries(backend, pack_id)]
        live_here = [e for e in entries if e.chunk_id in live]
        if live_here:
            index.add_pack(pack_id, entries)
            stats.notes.append(
                f"{name}: orphan pack held {len(live_here)} live "
                f"chunk(s) — adopted into index, not deleted")
            continue
        try:
            stats.bytes_reclaimed += backend.size(name)
            backend.delete(name)
            stats.orphan_packs_deleted += 1
        except BlobNotFound:
            pass

    return stats
