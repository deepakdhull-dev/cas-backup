
from __future__ import annotations

import json
import time

from .backend.base import Backend, BlobNotFound

CONFIG_NAME = "config"

REPO_FORMAT_VERSION: int = 1


class FormatError(Exception):


class NotARepository(FormatError):


def write_config(backend: Backend, *, chunker_params: dict,
                 scrypt_params: dict) -> dict:
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

    return config
