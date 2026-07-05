"""Snapshot records: the roots of everything (decision 8's top level).

WHAT A SNAPSHOT IS
==================
A tiny encrypted JSON blob under snapshots/<id> pointing at one Merkle
root, plus context:

    { "v": 1, "root_tree": <hex>, "created": <unix>,
      "hostname": ..., "source_path": ..., "stats": {...} }

Snapshots are the GC ROOTS: a chunk is live iff reachable from some
snapshot's root_tree (manifest.collect_reachable_ids). Deleting a
snapshot = deleting this blob; the tree and chunks it uniquely
referenced become garbage for the next prune. The blob is the entire
retention mechanism — no other bookkeeping exists or is needed.

SNAPSHOT IDS
============
16 random hex chars (8 bytes, os.urandom). NOT content-derived:
two backups of identical data at different times are distinct
snapshots (different created/stats) and must not collide into one
name. NOT timestamp-derived: two runs in the same second must not
collide either. Random ids sidestep both; CLI accepts unambiguous
prefixes like Git.

WHY SNAPSHOT BLOBS ARE ENCRYPTED
================================
source_path and hostname are metadata about YOUR machine; stats leak
data sizes. The repository's threat model (crypto.py: untrusted
storage) covers metadata, not just content. Sealed with the master
key, AAD "snapshot:<id>" — a valid snapshot blob copied under a
different id fails authentication (same substitution defense as
chunks).

THE ORDERING RULE, FINAL FORM
=============================
    create_snapshot: store.flush() FIRST, then put snapshot blob.

A snapshot must never exist before every chunk its tree references is
durable in the backend. With this rule, the crash-consistency story
of the ENTIRE SYSTEM collapses to one sentence: at any instant, every
snapshot blob present in the repository describes a fully restorable
state; anything else in flight is orphaned garbage awaiting GC. That
sentence is the system's contract, and it is enforced here.

MARK PHASE LIVES HERE
=====================
collect_live_ids() unions reachability over all snapshots — the
`live` set handed to cas.gc.collect(). It sits in backup/ (not cas/)
by the layering rule: only the client knows what a root is. prune's
lock must span BOTH this mark and the sweep; marking without the lock
races a concurrent backup whose new snapshot lands between mark and
sweep — its chunks, unmarked, would be swept. (The lock's whole
reason to exist, decision 15.)
"""

from __future__ import annotations

import json
import socket
import time
from dataclasses import dataclass

from ..cas import crypto, hasher
from ..cas.backend.base import Backend, BlobNotFound
from ..cas.objectstore import ObjectStore
from .manifest import collect_reachable_ids
from .scanner import ScanReport, scan_directory

SNAPSHOT_PREFIX = "snapshots/"
SNAPSHOT_VERSION = 1


class SnapshotError(Exception):
    pass


class SnapshotNotFound(SnapshotError):
    pass


@dataclass(frozen=True)
class Snapshot:
    id: str
    root_tree: bytes
    created: float
    hostname: str
    source_path: str
    stats: dict

    def to_payload(self) -> bytes:
        return json.dumps({
            "v": SNAPSHOT_VERSION,
            "root_tree": hasher.to_hex(self.root_tree),
            "created": self.created,
            "hostname": self.hostname,
            "source_path": self.source_path,
            "stats": self.stats,
        }).encode()

    @staticmethod
    def from_payload(sid: str, raw: bytes) -> "Snapshot":
        doc = json.loads(raw)
        if doc.get("v") != SNAPSHOT_VERSION:
            raise SnapshotError(
                f"snapshot {sid}: version {doc.get('v')!r} unsupported")
        return Snapshot(
            id=sid,
            root_tree=hasher.from_hex(doc["root_tree"]),
            created=doc["created"],
            hostname=doc["hostname"],
            source_path=doc["source_path"],
            stats=doc.get("stats", {}),
        )


def _name(sid: str) -> str:
    return f"{SNAPSHOT_PREFIX}{sid}"


def _aad(sid: str) -> bytes:
    return f"snapshot:{sid}".encode()


# ---------------------------------------------------------------------------
# Lifecycle
# ---------------------------------------------------------------------------

def create_snapshot(store: ObjectStore, backend: Backend, key: bytes,
                    source: str, exclude=None) -> tuple[Snapshot, ScanReport]:
    """Run a backup: scan -> flush -> snapshot blob. THE ordering rule.

    Caller holds the repository lock (repo.py's job)."""
    import os
    root_id, report = scan_directory(store, __import__("pathlib").Path(source),
                                     exclude=exclude)
    store.flush()                       # every referenced chunk durable...

    sid = os.urandom(8).hex()
    snap = Snapshot(
        id=sid,
        root_tree=root_id,
        created=time.time(),
        hostname=socket.gethostname(),
        source_path=str(source),
        stats={
            "files": report.files, "dirs": report.dirs,
            "symlinks": report.symlinks, "bytes_read": report.bytes_read,
            "chunks_new": report.chunks_new, "skipped": len(report.skipped),
        },
    )
    sealed = crypto.encrypt(key, snap.to_payload(), aad=_aad(sid))
    backend.put_bytes(_name(sid), sealed)      # ...before the root exists
    return snap, report


def load_snapshot(backend: Backend, key: bytes, sid: str) -> Snapshot:
    try:
        sealed = backend.get_bytes(_name(sid))
    except BlobNotFound:
        raise SnapshotNotFound(sid) from None
    raw = crypto.decrypt(key, sealed, aad=_aad(sid))
    return Snapshot.from_payload(sid, raw)


def list_snapshots(backend: Backend, key: bytes) -> list[Snapshot]:
    snaps = []
    for name in backend.list(SNAPSHOT_PREFIX):
        sid = name[len(SNAPSHOT_PREFIX):]
        snaps.append(load_snapshot(backend, key, sid))
    return sorted(snaps, key=lambda s: s.created)


def resolve_snapshot(backend: Backend, key: bytes, ref: str) -> Snapshot:
    """Accept a full id, an unambiguous prefix, or 'latest'."""
    snaps = list_snapshots(backend, key)
    if not snaps:
        raise SnapshotNotFound("repository has no snapshots")
    if ref == "latest":
        return snaps[-1]
    matches = [s for s in snaps if s.id.startswith(ref)]
    if not matches:
        raise SnapshotNotFound(ref)
    if len(matches) > 1:
        raise SnapshotError(
            f"snapshot ref {ref!r} is ambiguous: "
            f"{', '.join(s.id for s in matches)}")
    return matches[0]


def delete_snapshot(backend: Backend, sid: str) -> None:
    """Remove the root. Storage is reclaimed by the NEXT prune —
    deletion and reclamation are deliberately separate steps (mark-
    and-sweep rationale, cas/gc.py)."""
    try:
        backend.delete(_name(sid))
    except BlobNotFound:
        raise SnapshotNotFound(sid) from None


# ---------------------------------------------------------------------------
# GC mark phase
# ---------------------------------------------------------------------------

def collect_live_ids(store: ObjectStore, backend: Backend,
                     key: bytes) -> set[bytes]:
    """Union of reachable ids over ALL snapshots: the mark result.
    Caller must hold the lock across this AND the subsequent sweep."""
    live: set[bytes] = set()
    for snap in list_snapshots(backend, key):
        live |= collect_reachable_ids(store, snap.root_tree)
    return live
