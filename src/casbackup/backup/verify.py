from __future__ import annotations

from dataclasses import dataclass, field

from ..cas import hasher
from ..cas.backend.base import Backend, BlobNotFound
from ..cas.index import ChunkIndex
from ..cas.objectstore import ObjectStore, ObjectStoreError
from ..cas.packfile import PACK_PREFIX, pack_name
from .manifest import ManifestError, walk_tree
from .metadata import TYPE_FILE
from .snapshot import list_snapshots


@dataclass
class CheckReport:
    snapshots_checked: int = 0
    trees_walked: int = 0
    files_seen: int = 0
    chunks_referenced: int = 0
    chunks_missing: list[str] = field(default_factory=list)  # hex ids
    chunks_read: int = 0
    chunks_corrupt: list[str] = field(default_factory=list)  # hex ids
    packs_checked: int = 0
    pack_problems: list[str] = field(default_factory=list)
    orphan_packs: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)  # everything else

    @property
    def ok(self) -> bool:
        return not (
            self.chunks_missing
            or self.chunks_corrupt
            or self.pack_problems
            or self.errors
        )


def check(
    store: ObjectStore,
    index: ChunkIndex,
    backend: Backend,
    key: bytes,
    read_data: bool = False,
) -> CheckReport:
    """Run verification. See module docstring for tier semantics."""
    report = CheckReport()
    referenced: set[bytes] = set()

    # ---- tiers 1-3: snapshots -> trees -> reference existence -------------
    try:
        snaps = list_snapshots(backend, key)
    except Exception as exc:
        report.errors.append(f"snapshot listing failed: {exc}")
        snaps = []

    for snap in snaps:
        report.snapshots_checked += 1
        try:
            for _path, entry in walk_tree(store, snap.root_tree):
                if entry.meta.type == TYPE_FILE:
                    report.files_seen += 1
                    for cid in entry.chunks or ():
                        referenced.add(cid)
                else:
                    report.trees_walked += 1
            referenced.add(snap.root_tree)
        except (ManifestError, ObjectStoreError) as exc:
            report.errors.append(f"snapshot {snap.id}: tree walk failed: {exc}")

    report.chunks_referenced = len(referenced)
    for cid in referenced:
        if not index.has(cid):
            report.chunks_missing.append(hasher.to_hex(cid))

    # ---- tier 4: index <-> pack cross-check ---------------------------------
    backend_packs: set[bytes] = set()
    for name in backend.list(PACK_PREFIX):
        hex_part = name[len(PACK_PREFIX) :].removesuffix(".pack")
        try:
            backend_packs.add(hasher.from_hex(hex_part))
        except ValueError:
            report.pack_problems.append(f"{name}: unparseable pack name")

    indexed_packs: set[bytes] = set()
    for cid, pack_id in index.iter_all():
        indexed_packs.add(pack_id)
        located = index.get(cid)
        assert located is not None
        _pid, entry = located
        try:
            psize = backend.size(pack_name(pack_id))
        except BlobNotFound:
            report.pack_problems.append(
                f"chunk {hasher.to_hex(cid)}: indexed in missing pack "
                f"{hasher.to_hex(pack_id)}"
            )
            continue
        if entry.offset + entry.length > psize:
            report.pack_problems.append(
                f"chunk {hasher.to_hex(cid)}: geometry overruns pack "
                f"{hasher.to_hex(pack_id)} ({entry.offset}+{entry.length} "
                f"> {psize})"
            )
    report.packs_checked = len(indexed_packs)

    for pack_id in backend_packs - indexed_packs:
        report.orphan_packs.append(hasher.to_hex(pack_id))
        # reported only — prune owns deletion (read-only contract)

    # ---- tier 5: deep read (--read-data) --------------------------------------
    if read_data:
        for cid, _pack in index.iter_all():
            try:
                store.get(bytes(cid))
                report.chunks_read += 1
            except ObjectStoreError as exc:
                report.chunks_corrupt.append(hasher.to_hex(cid))
                report.errors.append(str(exc))

    return report
