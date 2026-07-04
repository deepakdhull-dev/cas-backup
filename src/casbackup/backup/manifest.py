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
    chunks: tuple[bytes, ...] | None = None  # files: ordered chunk ids
    file_hash: bytes | None = None  # files: whole-file sha256
    tree: bytes | None = None  # dirs: child node id


# ---------------------------------------------------------------------------
# Building and storing nodes
# ---------------------------------------------------------------------------


def _canonical(obj) -> bytes:
    return json.dumps(
        obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def store_tree_node(store: ObjectStore, entries: list[TreeEntry]) -> bytes:
    out = []
    for e in sorted(entries, key=lambda e: e.name):
        if not e.name or "/" in e.name or e.name in (".", ".."):
            raise ManifestError(f"illegal entry name: {e.name!r}")
        item: dict = {"name": e.name, "meta": e.meta.to_dict()}
        if e.meta.type == TYPE_FILE:
            item["chunks"] = [hasher.to_hex(c) for c in (e.chunks or ())]
            item["file_hash"] = hasher.to_hex(e.file_hash)  # type: ignore[arg-type]
        elif e.meta.type == TYPE_DIR:
            item["tree"] = hasher.to_hex(e.tree)  # type: ignore[arg-type]
        elif e.meta.type != TYPE_SYMLINK:
            raise ManifestError(f"unknown entry type: {e.meta.type!r}")
        out.append(item)

    return store.put(_canonical({"v": NODE_VERSION, "entries": out}))


# ---------------------------------------------------------------------------
# Loading and walking nodes
# ---------------------------------------------------------------------------


def load_tree_node(store: ObjectStore, tree_id: bytes) -> list[TreeEntry]:
    raw = store.get(tree_id)
    try:
        doc = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ManifestError(
            f"tree node {hasher.to_hex(tree_id)}: not JSON: {exc}"
        ) from exc
    if doc.get("v") != NODE_VERSION:
        raise ManifestError(
            f"tree node version {doc.get('v')!r} "
            f"unsupported (this build: {NODE_VERSION})"
        )

    entries: list[TreeEntry] = []
    for item in doc.get("entries", []):
        name = item.get("name")
        if not isinstance(name, str) or not name or "/" in name or name in (".", ".."):
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

        entries.append(
            TreeEntry(
                name=name, meta=meta, chunks=chunks, file_hash=file_hash, tree=tree
            )
        )
    return entries


def walk_tree(
    store: ObjectStore, tree_id: bytes, prefix: str = ""
) -> Iterator[tuple[str, TreeEntry]]:
    for entry in load_tree_node(store, tree_id):
        path = f"{prefix}{entry.name}"
        yield path, entry
        if entry.meta.type == TYPE_DIR:
            yield from walk_tree(store, entry.tree, prefix=f"{path}/")


def collect_reachable_ids(store: ObjectStore, tree_id: bytes) -> set[bytes]:
    live: set[bytes] = {tree_id}
    for _path, entry in walk_tree(store, tree_id):
        if entry.meta.type == TYPE_DIR:
            live.add(entry.tree)  # type: ignore[arg-type]
        elif entry.meta.type == TYPE_FILE:
            live.update(entry.chunks)  # type: ignore[arg-type]
    return live
