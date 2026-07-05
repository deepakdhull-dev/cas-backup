"""casbackup.cas — the content-addressable storage engine (decision 1).

Public surface of the engine. Clients (casbackup.backup, or anything
else) should import from here, not from submodules, so internal
reorganization never breaks them.

The engine's world model, in one paragraph: bytes go in as chunks
(chunker), get named by their content (hasher), stored once no matter
how often they recur (objectstore + index), packed into large
immutable blobs (packfile) on any storage that can hold named blobs
(backend), compressed and sealed (compress, crypto), guarded against
concurrent writers (lock), reclaimed when unreferenced (gc), all under
an explicitly versioned on-disk format (formatver). No files, no
directories, no snapshots — those are client concepts.
"""

from .chunker import AVG_SIZE, MAX_SIZE, MIN_SIZE, Chunk, chunk_bytes, chunk_stream
from .crypto import (DecryptionError, generate_key, unwrap_key, wrap_key)
from .formatver import (REPO_FORMAT_VERSION, FormatError, NotARepository,
                        read_config, write_config)
from .gc import GCStats, collect
from .hasher import DIGEST_SIZE, StreamingHasher, chunk_id, from_hex, to_hex
from .index import ChunkIndex, IndexError_
from .lock import LockError, RepositoryLock
from .objectstore import (ChunkNotFound, CorruptChunk, ObjectStore,
                          ObjectStoreError)
from .packfile import DEFAULT_PACK_SIZE, PackFormatError

__all__ = [
    "AVG_SIZE", "MAX_SIZE", "MIN_SIZE", "Chunk", "chunk_bytes", "chunk_stream",
    "DecryptionError", "generate_key", "unwrap_key", "wrap_key",
    "REPO_FORMAT_VERSION", "FormatError", "NotARepository", "read_config", "write_config",
    "GCStats", "collect",
    "DIGEST_SIZE", "StreamingHasher", "chunk_id", "from_hex", "to_hex",
    "ChunkIndex", "IndexError_",
    "LockError", "RepositoryLock",
    "ChunkNotFound", "CorruptChunk", "ObjectStore", "ObjectStoreError",
    "DEFAULT_PACK_SIZE", "PackFormatError",
]
