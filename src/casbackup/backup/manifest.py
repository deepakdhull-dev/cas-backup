"""Merkle-tree snapshot manifests (decision 8), stored IN the CAS.

THE CENTRAL TRICK OF THIS FILE
==============================
Tree nodes are themselves stored as chunks in the object store. A
directory serializes to a canonical byte string; ObjectStore.put()
of those bytes yields a tree id (its SHA-256) — same machinery,
same packs, same encryption as file data. Consequences, each large:

1. TREE-LEVEL DEDUP. An unchanged directory serializes to identical
   bytes -> identical id -> put() is a dedup hit -> the ENTIRE
   unchanged subtree (its node and, recursively, everything under
   it) is shared with prior snapshots at zero storage cost. Snapshot
   500 of a mostly-unchanged home directory stores a handful of new
   nodes along the path from root to each changed file. This is
   exactly Git's tree model.

2. MERKLE INTEGRITY. A node's id covers its bytes, which INCLUDE the
   ids of all children. The root id therefore transitively commits to
   every byte of every file and every metadata field of the snapshot.
   Verify the root against its id (free — verify-on-read) and each
   node against its parent's pointer, and NOTHING in a snapshot can
   be altered undetected. One 32-byte root id authenticates the
   entire tree.

3. FREE MACHINERY. Tree nodes get compression (JSON compresses
   hard), encryption, packing, GC participation — no parallel storage
   path to build or debug.

WHY CANONICALIZATION IS NON-NEGOTIABLE
======================================
Dedup consequence 1 holds only if serialization is DETERMINISTIC:
same logical directory -> same bytes, always. JSON offers no such
guarantee by default (key order, whitespace, float rendering, unicode
escaping can all vary). Canonical form used here:

    json.dumps(obj, sort_keys=True, separators=(",", ":"),
               ensure_ascii=False).encode("utf-8")

plus entries sorted by name. Any drift in this recipe silently halves
into "old nodes" and "new nodes" that never dedup against each other
— a performance bug invisible to correctness tests. The recipe is
therefore pinned by unit test.

NODE WIRE FORMAT (on-disk contract, versioned)
==============================================
    node := canonical JSON:
    {
      "v": 1,
      "entries": [
        {"name": ..., "meta": {...FileMeta...},
         one of:
           "chunks": [hex ids...], "file_hash": hex     (files)
           "tree": hex id                                (dirs)
           (symlinks carry target inside meta)
        }, ... sorted by name
      ]
    }

- Hex ids (not raw bytes) inside nodes: JSON cannot carry raw bytes;
  base64 would be smaller but hex matches every other human surface
  (CLI, logs) and zstd erases most of the difference.
- file_hash: whole-file SHA-256, computed streamingly during scan.
  Redundant with the chunk list in theory (chunks are individually
  verified); in practice it lets `check --deep` and restore assert
  END-TO-END file integrity with one comparison, catching bugs in
  chunk ORDERING that per-chunk checks cannot see (all chunks valid,
  sequence wrong).
- Directory names must not contain "/"; enforced at build time —
  a manifest is untrusted input to restore, and path traversal via a
  crafted entry name ("../../.bashrc") must die here, not in restore.

WHAT IS NOT IN THIS FILE
========================
No filesystem walking (scanner.py builds trees), no snapshot records
(snapshot.py points at root ids), no restore logic. This file is the
format: build a node, store a node, load a node, walk stored trees.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Iterator

from ..cas import hasher
from ..cas.objectstore import ObjectStore
from .metadata import TYPE_DIR, TYPE_FILE, TYPE_SYMLINK, FileMeta

NODE_VERSION = 1


class ManifestError(Exception):
    """Structurally invalid tree node — corrupt or hostile manifest."""


@dataclass(frozen=True)
class TreeEntry:
    """One directory member, decoded."""
    name: str
    meta: FileMeta
    chunks: tuple[bytes, ...] | None = None   # files: ordered chunk ids
    file_hash: bytes | None = None            # files: whole-file sha256
    tree: bytes | None = None                 # dirs: child node id


# ---------------------------------------------------------------------------
# Building and storing nodes
# ---------------------------------------------------------------------------

def _canonical(obj) -> bytes:
    """THE canonicalization recipe. Pinned by test; never vary."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False).encode("utf-8")


def store_tree_node(store: ObjectStore, entries: list[TreeEntry]) -> bytes:
    """Serialize a directory's entries canonically; store as a chunk.
    Returns the node's id. Dedup of unchanged directories happens
    inside store.put() — no special casing here."""
    out = []
    for e in sorted(entries, key=lambda e: e.name):
        if not e.name or "/" in e.name or e.name in (".", ".."):
            raise ManifestError(f"illegal entry name: {e.name!r}")
        item: dict = {"name": e.name, "meta": e.meta.to_dict()}
        if e.meta.type == TYPE_FILE:
            item["chunks"] = [hasher.to_hex(c) for c in (e.chunks or ())]
            item["file_hash"] = hasher.to_hex(e.file_hash)  # type: ignore[arg-type]
        elif e.meta.type == TYPE_DIR:
            item["tree"] = hasher.to_hex(e.tree)            # type: ignore[arg-type]
        elif e.meta.type != TYPE_SYMLINK:
            raise ManifestError(f"unknown entry type: {e.meta.type!r}")
        out.append(item)

    return store.put(_canonical({"v": NODE_VERSION, "entries": out}))


# ---------------------------------------------------------------------------
# Loading and walking nodes
# ---------------------------------------------------------------------------

def load_tree_node(store: ObjectStore, tree_id: bytes) -> list[TreeEntry]:
    """Fetch and decode one node. Integrity is already proven by
    store.get() (AEAD + id re-hash); this function's own validation
    targets STRUCTURE — a well-hashed node can still be hostile if the
    repository was written by an attacker with the key, and restore
    consumes what this returns."""
    raw = store.get(tree_id)
    try:
        doc = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ManifestError(f"tree node {hasher.to_hex(tree_id)}: "
                            f"not JSON: {exc}") from exc
    if doc.get("v") != NODE_VERSION:
        raise ManifestError(f"tree node version {doc.get('v')!r} "
                            f"unsupported (this build: {NODE_VERSION})")

    entries: list[TreeEntry] = []
    for item in doc.get("entries", []):
        name = item.get("name")
        if not isinstance(name, str) or not name or "/" in name \
                or name in (".", ".."):
            raise ManifestError(f"illegal entry name in node: {name!r}")
        meta = FileMeta.from_dict(item["meta"])

        chunks = file_hash = tree = None
        if meta.type == TYPE_FILE:
            chunks = tuple(hasher.from_hex(h) for h in item["chunks"])
            file_hash = hasher.from_hex(item["file_hash"])
        elif meta.type == TYPE_DIR:
            tree = hasher.from_hex(item["tree"])
        elif meta.type == TYPE_SYMLINK:
            if meta.link_target is None:
                raise ManifestError(f"symlink entry {name!r} lacks target")
        else:
            raise ManifestError(f"unknown entry type {meta.type!r}")

        entries.append(TreeEntry(name=name, meta=meta, chunks=chunks,
                                 file_hash=file_hash, tree=tree))
    return entries


def walk_tree(store: ObjectStore, tree_id: bytes,
              prefix: str = "") -> Iterator[tuple[str, TreeEntry]]:
    """Depth-first traversal yielding (relative_path, entry) for every
    entry under a root. The shared engine of restore, list, verify,
    and GC's mark phase."""
    for entry in load_tree_node(store, tree_id):
        path = f"{prefix}{entry.name}"
        yield path, entry
        if entry.meta.type == TYPE_DIR:
            yield from walk_tree(store, entry.tree, prefix=f"{path}/")


def collect_reachable_ids(store: ObjectStore, tree_id: bytes) -> set[bytes]:
    """Every chunk id reachable from a root: tree node ids AND file
    chunk ids. GC's mark phase for one snapshot; prune unions this
    across all live snapshots. Tree nodes MUST be in the live set —
    they are chunks too, and sweeping them destroys the manifest."""
    live: set[bytes] = {tree_id}
    for _path, entry in walk_tree(store, tree_id):
        if entry.meta.type == TYPE_DIR:
            live.add(entry.tree)          # type: ignore[arg-type]
        elif entry.meta.type == TYPE_FILE:
            live.update(entry.chunks)     # type: ignore[arg-type]
    return live
