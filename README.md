# casbackup

A content-addressable, deduplicating, encrypted backup tool. Files are
split into chunks by content, each unique chunk is stored exactly once
across every snapshot, and snapshots reassemble them on restore. Same
architecture family as [restic] and [borg]; built from scratch as a
teaching implementation of the underlying storage engine.

The core is a general-purpose content-addressable store (`casbackup.cas`).
The backup application is one client of it (`casbackup.backup`).

[restic]: https://restic.net
[borg]: https://www.borgbackup.org

## What it does that `cp -r` doesn't

- Splits files at content-defined boundaries (FastCDC). A one-byte
  edit in a 20 GB VM image adds one chunk, not 20 GB.
- Names every chunk by SHA-256 of its content. A chunk already stored
  is never stored again — across files, across snapshots, forever.
- Serializes directories as canonical Merkle-tree nodes, themselves
  stored as chunks. An unchanged subtree dedups whole.
- Encrypts everything (AES-256-GCM) with an AAD-bound identity, so
  substituted or reordered ciphertexts fail authentication.
- Verifies three integrity layers on every restored byte (AEAD tag,
  per-chunk hash, whole-file hash).
- Reclaims space with mark-and-sweep GC and repack economics when
  snapshots are deleted.
- Requires no journal. Crash consistency follows from strict write
  ordering: any snapshot record present on disk is fully restorable.

## Project structure

```
casbackup/
├── pyproject.toml
├── README.md
├── LICENSE
│
├── src/casbackup/
│   ├── __main__.py         python -m casbackup
│   ├── repo.py             composition root — wires every layer together
│   ├── config.py           TOML config + passphrase resolution
│   │
│   ├── cas/                THE STORAGE ENGINE (knows only chunks)
│   │   ├── chunker.py          FastCDC content-defined chunking
│   │   ├── hasher.py           SHA-256 chunk identity
│   │   ├── compress.py         zstd, with stored-raw fallback
│   │   ├── crypto.py           AES-256-GCM + scrypt key wrap
│   │   ├── packfile.py         immutable pack container format
│   │   ├── objectstore.py      public API: put / get / has
│   │   ├── index.py            LMDB: chunk id → pack location
│   │   ├── gc.py               mark-and-sweep + repack
│   │   ├── lock.py             advisory lock, staleness detection
│   │   ├── formatver.py        on-disk format versioning
│   │   └── backend/
│   │       ├── base.py             named-blob interface
│   │       └── local.py            local filesystem implementation
│   │
│   ├── backup/             THE BACKUP CLIENT (knows files, dirs, snapshots)
│   │   ├── metadata.py         perms / owner / mtime capture + apply
│   │   ├── manifest.py         Merkle tree nodes
│   │   ├── scanner.py          directory walk → chunk pipeline
│   │   ├── snapshot.py         snapshot records; GC mark phase
│   │   ├── restore.py          streaming full + single-file restore
│   │   └── verify.py           check / scrub
│   │
│   └── cli/                COMMAND-LINE INTERFACE
│       ├── main.py             click entrypoint
│       └── cmd_*.py            init, backup, restore, list, check, prune
│
├── tests/
│   ├── unit/               per-module tests (11 files)
│   └── integration/        backup cycle, dedup, crash recovery, check
│
└── docs/
    ├── architecture.md     layer diagram, data flow, invariants
    ├── format-spec.md      on-disk format contract (versioned)
    └── decisions.md        21-decision log with rejected alternatives
```

Dependency direction: `backup/` imports `cas/`; `cas/` never imports
`backup/`. `repo.py` is the only module that constructs the object
graph.

## Repository layout on disk

```
<repo>/
├── config          format version + creation-time parameters (plaintext)
├── keys/master     scrypt salt || wrapped master key
├── packs/*.pack    immutable ~64 MiB chunk containers
├── snapshots/*     encrypted snapshot records (the GC roots)
├── locks/*         advisory writer locks (transient)
└── index.lmdb/     local derived cache — rebuildable from packs
```

Byte-level spec: [`docs/format-spec.md`](docs/format-spec.md).

## Architecture 

```
                    ┌─────────────────────────────┐
                    │           cli/              │  argparse-level UX,
                    │  init backup restore list   │  exit codes, output
                    │        check prune          │
                    └──────────────┬──────────────┘
                                   │
                    ┌──────────────▼──────────────┐
                    │   repo.py (composition root) │  ONLY place layers
                    │   config.py (operator TOML)  │  are wired together
                    └──────┬───────────────┬──────┘
                           │               │
            ┌──────────────▼───┐   ┌───────▼──────────────────┐
            │     backup/      │   │   uses cas/ public API    │
            │ scanner manifest │──▶│                           │
            │ snapshot restore │   │  files/dirs/snapshots     │
            │ metadata verify  │   │  exist ONLY on this side  │
            └──────────────────┘   └───────────────────────────┘
                           │
            ┌──────────────▼──────────────────────────────────┐
            │                    cas/                          │
            │                                                  │
            │  objectstore  ◀─ put/get/has by chunk id         │
            │  ├─ chunker   (FastCDC boundaries)               │
            │  ├─ hasher    (SHA-256 identity)                 │
            │  ├─ compress  (zstd-or-stored framing)           │
            │  ├─ crypto    (AES-256-GCM, AAD-bound)           │
            │  ├─ packfile  (immutable containers)             │
            │  ├─ index     (LMDB, derived cache)              │
            │  ├─ gc        (mark-and-sweep + repack)          │
            │  ├─ lock      (advisory, metadata-carrying)      │
            │  ├─ formatver (version gate)                     │
            │  └─ backend/  (named-blob interface + local impl)│
            └──────────────────────────────────────────────────┘
```

## Requirements

- Python 3.11 or newer.
- Linux, macOS, or WSL. Native Windows is untested.
- Dependencies (installed automatically): `lmdb`, `zstandard`,
  `cryptography`, `click`.

## Install

```
pip install .
```

Development (editable install with test dependencies):

```
pip install -e ".[dev]"
```

Installs a `casbackup` command on `$PATH`. If the scripts directory is
not on `$PATH`, invoke as `python -m casbackup`.

## Quick start

```
# Create a repository. Prompts for a passphrase, twice.
casbackup -r /mnt/backup/repo init

# Back up a directory.
casbackup -r /mnt/backup/repo backup ~/projects

# Change something, back up again — only new chunks are stored.
casbackup -r /mnt/backup/repo backup ~/projects

# List snapshots.
casbackup -r /mnt/backup/repo list

# Restore the latest snapshot into a fresh directory.
casbackup -r /mnt/backup/repo restore latest /tmp/restored

# Restore one file from a specific snapshot.
casbackup -r /mnt/backup/repo restore 91b8e5ab /tmp/report.pdf \
    --path docs/report.pdf

# Verify integrity. Structural is cheap; --read-data reads everything.
casbackup -r /mnt/backup/repo check
casbackup -r /mnt/backup/repo check --read-data

# Delete an old snapshot and reclaim its unique storage.
casbackup -r /mnt/backup/repo prune --forget 91b8e5ab
```

The passphrase is unrecoverable if lost. No backdoor, no reset.

## Commands

| command | purpose |
|---|---|
| `init` | Create a new repository. Prompts twice for the passphrase. |
| `backup SOURCE` | Snapshot a directory. |
| `restore REF TARGET [--path P] [--force]` | Restore snapshot `REF` (id, unambiguous prefix, or `latest`) into `TARGET`. `--path` restores a single entry. `--force` overwrites existing targets. |
| `list [REF]` | List snapshots. With `REF`, list one snapshot's contents. |
| `check [--read-data] [--rebuild-index]` | Verify integrity. Deep mode reads every stored byte. Rebuild reconstructs the local index from pack scans. |
| `prune [--forget REF]...` | Delete snapshots and garbage-collect unreferenced chunks. |

Exit codes: `0` success, `1` operational error (bad passphrase, lock
held, missing snapshot), `2` usage error, `3` integrity or restore
failure.

## Configuration

Optional TOML at `~/.config/casbackup/config.toml` (override with
`--config PATH` or `$CASBACKUP_CONFIG`):

```toml
repository = "/mnt/backup/repo"
excludes = ["*.pyc", "__pycache__", ".venv", "node_modules"]
pack_size = 67108864          # 64 MiB
repack_threshold = 0.20       # repack a mixed pack when >= 20% dead
# passphrase_file = "~/.config/casbackup/pass"   # must be chmod 600
```

Passphrase resolution order:

1. `$CASBACKUP_PASSPHRASE`
2. `passphrase_file` (mode-checked; refuses group/world-readable files)
3. Interactive prompt

Passphrases inline in the config file are refused by design.

## Tests

```
pip install -e ".[dev]"
pytest
pytest --cov=casbackup
```

103 tests, ~15 seconds. Property tests (Hypothesis) cover chunker
reconstruction. Integration tests drive real backups and restores
against real filesystems, including manufactured crash scenarios.

## Known limitations (v1, deliberate)

- Single-threaded. Pure-Python chunking sets the throughput ceiling.
  Suited to tens of GB per run, not petabyte scale.
- Local filesystem backend only. The backend interface is designed
  for S3/SFTP additions; no remote implementation ships in v1.
- Chunk ids appear in cleartext in pack headers. An attacker holding
  the repository can confirm whether a known plaintext is present by
  hashing it. Content confidentiality is unaffected. Closing this
  requires a format version bump.
- Hardlink identity is not preserved. Contents dedup; restore yields
  independent files.
- Sockets, FIFOs, and device nodes are skipped and reported.
- The advisory lock has a small TOCTOU window. No cross-backend
  compare-and-swap primitive is available. Suited to single-user use.

Rationale for every choice and every rejected alternative:
[`docs/decisions.md`](docs/decisions.md).

## License

MIT.
