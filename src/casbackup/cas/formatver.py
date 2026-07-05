"""Repository format versioning (decision 21).

THE PROBLEM VERSIONING SOLVES
=============================
On-disk formats outlive the code that wrote them. The day any format
element changes — pack entry layout, index value width, manifest
encoding, KDF parameters, compression tags — three populations of
repository exist simultaneously: old repos read by new code, new repos
read by old code, and repos mid-migration. Without an explicit version
number, all three fail as undiagnosable corruption. With one, each
becomes a decidable case with a precise error message or a migration
path.

The rule this file enforces repository-wide: EVERY reader checks the
version BEFORE interpreting any bytes; every writer stamps what it
writes. Sub-formats with independent lifecycles carry their own
version (pack files already do: PACK_FORMAT_VERSION in packfile.py;
compression tags in compress.py are a micro-version). This file owns
the TOP-LEVEL repository version and the compatibility policy.

COMPATIBILITY POLICY (the actual decision content)
==================================================
    repo version == supported     -> proceed
    repo version <  supported     -> proceed IF a reader for it is
                                     retained; migration tooling may
                                     upgrade in place. v1 ships only
                                     version 1, so this branch is
                                     currently unreachable — the
                                     policy exists so version 2 has
                                     rules to follow, not improvise.
    repo version >  supported     -> HARD STOP. Never guess forward.
                                     Reading a future format with old
                                     assumptions is how backups get
                                     silently mangled. The error names
                                     both versions and the fix
                                     (upgrade the tool).

WHERE THE VERSION LIVES
=======================
Blob "config" at the repository root: a small JSON document, first
thing `init` writes, first thing `open` reads. JSON rather than a raw
byte: the config blob will accumulate repository-scoped settings
(chunker params if ever made tunable, scrypt parameters, pack size),
and those settings belong WITH the version because they are format-
adjacent — a repo chunked at different parameters is de-facto a
different dedup domain.

Version 1 config schema:
    {
      "format_version": 1,
      "created": <unix time>,
      "chunker": {"min": 16384, "avg": 65536, "max": 262144},
      "scrypt": {"n": 32768, "r": 8, "p": 1}
    }

The chunker/scrypt blocks record what the repo was CREATED with, so
future code with different defaults still operates this repo with the
original parameters (changing chunker params mid-repo silently kills
dedup against all existing data — recording them is the guard).
"""

from __future__ import annotations

import json
import time

from .backend.base import Backend, BlobNotFound

CONFIG_NAME = "config"

# The single top-level repository format version this build reads and
# writes. Bump ONLY with a documented migration story in
# docs/format-spec.md.
REPO_FORMAT_VERSION: int = 1


class FormatError(Exception):
    """Repository format cannot be handled by this build."""


class NotARepository(FormatError):
    """No config blob where one was expected — path is not a repo,
    distinct from a repo we cannot read."""


def write_config(backend: Backend, *, chunker_params: dict,
                 scrypt_params: dict) -> dict:
    """Stamp a NEW repository. Called exactly once, by `init`.

    Refuses to overwrite an existing config: re-initializing a live
    repository is always an operator error, never a recovery step.
    """
    if backend.exists(CONFIG_NAME):
        raise FormatError("repository already initialized (config exists)")
    config = {
        "format_version": REPO_FORMAT_VERSION,
        "created": time.time(),
        "chunker": chunker_params,
        "scrypt": scrypt_params,
    }
    backend.put_bytes(CONFIG_NAME, json.dumps(config, indent=2).encode())
    return config


def read_config(backend: Backend) -> dict:
    """Load and gate on the repository config. Every open path funnels
    through here BEFORE touching any other blob."""
    try:
        raw = backend.get_bytes(CONFIG_NAME)
    except BlobNotFound:
        raise NotARepository(
            "no repository config found — not an initialized repository"
        ) from None

    try:
        config = json.loads(raw)
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise FormatError(f"repository config unreadable: {exc}") from exc

    version = config.get("format_version")
    if not isinstance(version, int):
        raise FormatError("repository config missing format_version")

    if version > REPO_FORMAT_VERSION:
        raise FormatError(
            f"repository is format v{version}; this build supports up to "
            f"v{REPO_FORMAT_VERSION}. Upgrade casbackup to operate this "
            f"repository — refusing to guess at a newer format.")
    # version < supported: no older versions exist yet (v1 is first).
    # The migration branch materializes with v2; see module docstring.

    return config
