"""casbackup.backup — the backup client of the CAS engine (decision 1).

This package owns every concept the engine deliberately lacks: files,
directories, metadata, snapshots, restore. It consumes the engine
exclusively through casbackup.cas public surface; the dependency arrow
points one way. Any other client of the engine would sit beside this
package, not inside it.
"""

from .manifest import (ManifestError, TreeEntry, collect_reachable_ids,
                       load_tree_node, store_tree_node, walk_tree)
from .metadata import TYPE_DIR, TYPE_FILE, TYPE_SYMLINK, FileMeta
from .restore import RestoreError, RestoreReport, restore_single, restore_tree
from .scanner import ScanReport, scan_directory
from .snapshot import (Snapshot, SnapshotError, SnapshotNotFound,
                       collect_live_ids, create_snapshot, delete_snapshot,
                       list_snapshots, load_snapshot, resolve_snapshot)
from .verify import CheckReport, check

__all__ = [
    "ManifestError", "TreeEntry", "collect_reachable_ids",
    "load_tree_node", "store_tree_node", "walk_tree",
    "TYPE_DIR", "TYPE_FILE", "TYPE_SYMLINK", "FileMeta",
    "RestoreError", "RestoreReport", "restore_single", "restore_tree",
    "ScanReport", "scan_directory",
    "Snapshot", "SnapshotError", "SnapshotNotFound", "collect_live_ids",
    "create_snapshot", "delete_snapshot", "list_snapshots", "load_snapshot",
    "resolve_snapshot",
    "CheckReport", "check",
]
