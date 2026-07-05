"""Repository: the composition root (the only file that wires layers).

WHY A COMPOSITION ROOT
======================
Every module so far takes its collaborators as constructor arguments
(ObjectStore takes a Backend, an index, a key) and none constructs its
own. That discipline needs exactly one place where construction DOES
happen — here. Benefits of confining wiring to one file: swapping
LocalBackend for S3Backend is a one-line change here and zero lines
anywhere else; tests wire mock graphs freely because nothing
self-assembles; reading this file top to bottom IS the architecture
diagram.

REPOSITORY LAYOUT ON DISK (local backend)
=========================================
    <repo>/
      config            formatver blob: version + creation parameters
      keys/master       scrypt salt || wrapped master key
      packs/…           immutable chunk containers
      snapshots/…       encrypted snapshot records (the GC roots)
      locks/…           advisory writer lock
      index.lmdb/       LOCAL derived cache — never authoritative
                        (rebuildable from packs; would live in
                        ~/.cache for a remote backend)

KEY STORAGE — APPLIED DECISION, FLAGGED FOR VETO
================================================
The wrapped master key lives INSIDE the repository (keys/master):
salt (16 bytes) || sealed key blob. Rationale: the repository is
self-contained — copy the directory, know the passphrase, restore
anywhere; no second file to lose. Cost: an attacker with the repo can
mount an offline passphrase attack (scrypt parameters exist precisely
to price that attack). The alternative (external keyfile = second
factor) is a real hardening option deferred as a future `key`
subcommand. Veto relocates the key.

OPEN SEQUENCE (order is load-bearing)
=====================================
  1. read_config      — format gate BEFORE touching anything else
  2. unwrap key       — fails fast on wrong passphrase (GCM tag)
  3. open index       — LMDB map sized from operator config
  4. build ObjectStore
Init is the same in reverse plus generate/wrap. Both funnel every
caller through identical construction — the CLI never hand-builds.

LOCKING POLICY
==============
  backup, prune  -> exclusive writer lock (mutate repository state)
  restore, list, check -> lockless (read-only; LMDB read snapshots
                          give consistency; a check racing a backup
                          may see orphan packs — reported, harmless)
prune's lock spans MARK AND SWEEP together (snapshot.py rationale:
a snapshot landing between them would have its chunks swept).
"""

from __future__ import annotations

from pathlib import Path

from .cas import (ChunkIndex, ObjectStore, RepositoryLock, collect,
                  generate_key, read_config, unwrap_key, wrap_key,
                  write_config)
from .cas.backend import Backend, BlobNotFound, LocalBackend
from .cas.chunker import AVG_SIZE, MAX_SIZE, MIN_SIZE
from .cas.crypto import (SCRYPT_N, SCRYPT_P, SCRYPT_R, SALT_SIZE,
                         DecryptionError)
from .cas.gc import GCStats
from .backup import (CheckReport, RestoreReport, ScanReport, Snapshot,
                     check, collect_live_ids, create_snapshot,
                     delete_snapshot, list_snapshots, resolve_snapshot,
                     restore_single, restore_tree)
from .config import Config

KEY_NAME = "keys/master"
INDEX_DIRNAME = "index.lmdb"


class RepositoryError(Exception):
    pass


def init_repository(path: str | Path, passphrase: str,
                    cfg: Config | None = None) -> None:
    """Create a new repository. Refuses to reuse an initialized one
    (write_config enforces)."""
    cfg = cfg or Config()
    backend = LocalBackend(path)

    write_config(
        backend,
        chunker_params={"min": MIN_SIZE, "avg": AVG_SIZE, "max": MAX_SIZE},
        scrypt_params={"n": SCRYPT_N, "r": SCRYPT_R, "p": SCRYPT_P},
    )

    master = generate_key()
    salt, wrapped = wrap_key(master, passphrase)
    backend.put_bytes(KEY_NAME, salt + wrapped)


class Repository:
    """An open repository session: the object the CLI drives.

    Context manager; close() flushes the store and closes the index.
    """

    def __init__(self, path: str | Path, passphrase: str,
                 cfg: Config | None = None) -> None:
        self.cfg = cfg or Config()
        self.path = Path(path)
        self.backend: Backend = LocalBackend(self.path)

        # 1. format gate
        self.repo_config = read_config(self.backend)

        # 2. key unwrap — GCM tag doubles as the passphrase check
        try:
            raw = self.backend.get_bytes(KEY_NAME)
        except BlobNotFound:
            raise RepositoryError(
                "repository has no key blob (keys/master) — corrupt or "
                "partially initialized") from None
        salt, wrapped = raw[:SALT_SIZE], raw[SALT_SIZE:]
        sp = self.repo_config.get("scrypt", {})
        try:
            self.key = unwrap_key(salt, wrapped, passphrase,
                                  n=sp.get("n", SCRYPT_N),
                                  r=sp.get("r", SCRYPT_R),
                                  p=sp.get("p", SCRYPT_P))
        except DecryptionError:
            raise RepositoryError("wrong passphrase") from None

        # 3-4. index + store
        self.index = ChunkIndex(self.path / INDEX_DIRNAME,
                                map_size=self.cfg.index_map_size)
        self.store = ObjectStore(self.backend, self.index, self.key,
                                 pack_size=self.cfg.pack_size)

    # -- operations (thin: real logic lives in the layers) --------------------

    def backup(self, source: str) -> tuple[Snapshot, ScanReport]:
        with RepositoryLock(self.backend, operation="backup"):
            return create_snapshot(self.store, self.backend, self.key,
                                   source, exclude=self.cfg.exclude_fn())

    def snapshots(self) -> list[Snapshot]:
        return list_snapshots(self.backend, self.key)

    def resolve(self, ref: str) -> Snapshot:
        return resolve_snapshot(self.backend, self.key, ref)

    def restore(self, ref: str, target: str,
                path: str | None = None,
                force: bool = False) -> RestoreReport:
        snap = self.resolve(ref)
        if path:
            return restore_single(self.store, snap.root_tree, path,
                                  Path(target), refuse_overwrite=not force)
        return restore_tree(self.store, snap.root_tree, Path(target),
                            refuse_overwrite=not force)

    def forget(self, ref: str) -> str:
        """Delete a snapshot record. Space returns at next prune."""
        snap = self.resolve(ref)
        delete_snapshot(self.backend, snap.id)
        return snap.id

    def prune(self) -> GCStats:
        """Mark and sweep under ONE lock (module docstring)."""
        with RepositoryLock(self.backend, operation="prune"):
            live = collect_live_ids(self.store, self.backend, self.key)
            return collect(self.backend, self.index, live,
                           repack_threshold=self.cfg.repack_threshold)

    def check(self, read_data: bool = False) -> CheckReport:
        return check(self.store, self.index, self.backend, self.key,
                     read_data=read_data)

    def rebuild_index(self) -> int:
        """Repair path: reconstruct the derived index from pack scans."""
        from .cas import hasher
        from .cas.packfile import PACK_PREFIX
        with RepositoryLock(self.backend, operation="rebuild-index"):
            pack_ids = []
            for name in self.backend.list(PACK_PREFIX):
                hex_part = name[len(PACK_PREFIX):].removesuffix(".pack")
                try:
                    pack_ids.append(hasher.from_hex(hex_part))
                except ValueError:
                    continue
            return self.index.rebuild(self.backend, pack_ids)

    # -- lifecycle --------------------------------------------------------------

    def close(self) -> None:
        self.store.close()
        self.index.close()

    def __enter__(self) -> "Repository":
        return self

    def __exit__(self, *exc) -> None:
        if exc == (None, None, None):
            self.close()
        else:
            self.index.close()
