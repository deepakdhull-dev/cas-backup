"""Storage backend interface (decision 14).

WHY AN ABSTRACTION LAYER EXISTS AT ALL
======================================
Everything above this layer (object store, pack files, index, locks)
manipulates *named blobs*: "write these bytes under this name", "read
bytes 4096..8192 of that name". Nothing above cares whether the name
resolves to a local file, an S3 object, or a file on an SSH server.

Codifying that indifference as an interface NOW — while only the local
implementation exists — is what makes remote backends a pure addition
later instead of a rewrite. The alternative (open() calls scattered
through objectstore/packfile/lock code) welds the engine to the local
filesystem; retrofitting an abstraction under welded code is the
classic technical-debt trap decision 14 explicitly rejected.

THE INTERFACE IS DELIBERATELY NARROW
====================================
Only operations every plausible backend (POSIX fs, S3, SFTP) can
support cheaply:

    put_bytes / put_file   — create a named blob, ATOMICALLY
    get_bytes              — read a whole blob
    get_range              — read a byte range of a blob
    exists / size          — metadata probes
    list                   — enumerate names under a prefix
    delete                 — remove a blob

Deliberately ABSENT, and why:

- append / partial overwrite: S3 objects are immutable; SFTP append is
  unreliable. The pack format (packfile.py) is designed around
  write-once blobs specifically so backends never need mutation.
- rename/move: not universally atomic remotely. Higher layers never
  rename; they write final names only.
- directory concepts: names are flat strings with '/' separators;
  whether a backend materializes directories is its own business.

get_range is the one non-trivial requirement: restoring a single file
(decision 16) must not download an entire 64 MiB pack to extract one
64 KiB chunk. Every serious target supports it (pread locally, HTTP
Range on S3, seek on SFTP), so it earns its place.

THE ATOMICITY CONTRACT — MOST IMPORTANT PARAGRAPH IN THIS FILE
==============================================================
put_bytes / put_file MUST be all-or-nothing: after a crash at any
moment, a reader must see either the complete blob under its final
name, or no blob at all — NEVER a truncated file under the final name.

Everything crash-safety-related upstack leans on this single guarantee:
packs are referenced by the index only after the pack blob exists;
manifests reference chunks only after packs exist; snapshots reference
manifests last. Write ordering + atomic puts = a crash leaves at worst
orphaned garbage (reclaimed by GC, decision 13), never a reachable
reference to missing/partial data.

Local implementation strategy (backend/local.py): write to a temp name
in the same directory, fsync, rename over the final name — rename
within one POSIX filesystem is atomic. S3 gets this for free (PUT is
atomic by API contract).

NAMESPACE LAYOUT (fixed by this layer's callers; documented here so
backend implementers know what traffic to expect)

    packs/<hex>.pack       large write-once blobs (~64 MiB)
    manifests/<hex>        small blobs, one per snapshot tree node set
    snapshots/<name>       tiny blobs, one per snapshot
    keys/<name>            key material (crypto.py wrap output)
    locks/<name>           lock files (lock.py)
    config                 repository config blob

Small, hot, mutable-ish state (the LMDB chunk index) is deliberately
NOT stored through the backend: LMDB requires mmap on a local file.
The index is a local *cache* reconstructible by scanning packs
(packfile.py per-entry headers exist for exactly this), so it never
needs to live on the remote side. This split — authoritative data
remote-capable, derived index local — is how restic works too.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Iterator


class BackendError(Exception):
    """Base class for backend failures (I/O errors, missing blobs).

    Backends translate their native exceptions (OSError, boto errors,
    paramiko errors) into this hierarchy so upper layers handle one
    exception family regardless of backend.
    """


class BlobNotFound(BackendError):
    """Requested name does not exist in the backend."""


class Backend(ABC):
    """Abstract named-blob store. See module docstring for the contract.

    Names: non-empty strings, '/' as separator, no leading '/', no '..'
    components. Implementations must validate this (path traversal via
    a crafted manifest must be impossible).
    """

    # -- writes ------------------------------------------------------------

    @abstractmethod
    def put_bytes(self, name: str, data: bytes) -> None:
        """Atomically create blob `name` with content `data`.

        Overwrite semantics: replacing an existing name must also be
        atomic (readers see old blob or new blob, never a mix). Upper
        layers only overwrite tiny control blobs (config, snapshots);
        packs and manifests are write-once by construction.
        """

    @abstractmethod
    def put_file(self, name: str, local_path: str) -> None:
        """Atomically create blob `name` from a local file's content.

        Exists so multi-MiB packs stream from their staging file
        without a full in-memory copy (put_bytes would need one).
        """

    # -- reads -------------------------------------------------------------

    @abstractmethod
    def get_bytes(self, name: str) -> bytes:
        """Read entire blob. Raises BlobNotFound if absent."""

    @abstractmethod
    def get_range(self, name: str, offset: int, length: int) -> bytes:
        """Read exactly `length` bytes starting at `offset`.

        Raises BlobNotFound if absent; BackendError if the range
        extends past end-of-blob (indicates index/pack disagreement —
        upper layers treat it as corruption, so it must not be
        silently short-read).
        """

    # -- probes ------------------------------------------------------------

    @abstractmethod
    def exists(self, name: str) -> bool: ...

    @abstractmethod
    def size(self, name: str) -> int:
        """Blob size in bytes. Raises BlobNotFound if absent."""

    # -- enumeration -------------------------------------------------------

    @abstractmethod
    def list(self, prefix: str) -> Iterator[str]:
        """Yield all blob names starting with `prefix`, in unspecified
        order. Used by GC (enumerate packs/manifests) and `check`.
        """

    # -- deletion ----------------------------------------------------------

    @abstractmethod
    def delete(self, name: str) -> None:
        """Remove a blob. Deleting a nonexistent name raises
        BlobNotFound — GC wants to know if its worldview is stale.
        """
