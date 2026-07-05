"""Configuration (decision 20: config file support).

WHAT BELONGS IN CONFIG VS THE REPOSITORY
========================================
Two kinds of setting exist and conflating them corrupts repositories:

REPOSITORY-BOUND (live in the repo's config blob, formatver.py):
  chunker parameters, scrypt parameters. These describe HOW THE DATA
  WAS WRITTEN. Changing chunker params against an existing repo
  silently zeroes dedup against all prior data (new boundaries never
  match old ones); changing scrypt params makes the wrapped key
  un-unwrappable. They are recorded at init and read back at open —
  the config FILE never overrides them.

OPERATOR-BOUND (live in this file's TOML):
  repository path, exclude patterns, pack size, index map size,
  repack threshold, passphrase source. These describe HOW THIS
  MACHINE OPERATES the repo. All safe to vary run-to-run.

TOML, NOT YAML/JSON
===================
tomllib is stdlib since Python 3.11 (zero dependency), TOML has no
YAML footguns (the Norway problem: `no` parsing as boolean false;
implicit type coercion), and comments — which JSON lacks and config
files need.

PASSPHRASE SOURCING — APPLIED DECISION, FLAGGED FOR VETO
========================================================
Flagged pending in crypto.py; resolved here because the CLI cannot
exist without it. Applied policy:

  1. CASBACKUP_PASSPHRASE environment variable, if set
  2. `passphrase_file` config key (path whose CONTENT is the
     passphrase), if set — mode-checked: refuses group/world-readable
  3. interactive prompt (getpass) as fallback

NEVER a `passphrase = "..."` key in the TOML itself: config files get
committed to dotfile repos and synced to cloud storage reflexively;
an inline secret there is a breach-by-default design. The wrapped
master key lives INSIDE the repository (keys/master) — the repo is
self-contained; the passphrase is the only external secret.
Passphrase-less operation: not offered. Veto reopens both choices.

SEARCH ORDER
============
  --config PATH  >  $CASBACKUP_CONFIG  >  ~/.config/casbackup/config.toml
Absent file = pure defaults; config is optional, flags override file.
"""

from __future__ import annotations

import os
import stat
import sys
import tomllib
from dataclasses import dataclass, field
from pathlib import Path

from .cas.index import DEFAULT_MAP_SIZE
from .cas.gc import DEFAULT_REPACK_THRESHOLD
from .cas.packfile import DEFAULT_PACK_SIZE

DEFAULT_CONFIG_PATH = Path.home() / ".config" / "casbackup" / "config.toml"
ENV_CONFIG = "CASBACKUP_CONFIG"
ENV_PASSPHRASE = "CASBACKUP_PASSPHRASE"


class ConfigError(Exception):
    pass


@dataclass
class Config:
    """Operator-bound settings with production defaults."""
    repository: str | None = None
    passphrase_file: str | None = None
    pack_size: int = DEFAULT_PACK_SIZE
    index_map_size: int = DEFAULT_MAP_SIZE
    repack_threshold: float = DEFAULT_REPACK_THRESHOLD
    excludes: list[str] = field(default_factory=list)

    @staticmethod
    def load(explicit_path: str | None = None) -> "Config":
        """Search-order load (module docstring). Unknown keys are an
        error, not a warning: a typo'd `repositry` silently ignored
        means backups to the wrong place."""
        path: Path | None = None
        if explicit_path:
            path = Path(explicit_path)
            if not path.is_file():
                raise ConfigError(f"config file not found: {path}")
        elif os.environ.get(ENV_CONFIG):
            path = Path(os.environ[ENV_CONFIG])
            if not path.is_file():
                raise ConfigError(f"$CASBACKUP_CONFIG points at nothing: {path}")
        elif DEFAULT_CONFIG_PATH.is_file():
            path = DEFAULT_CONFIG_PATH

        if path is None:
            return Config()

        try:
            with open(path, "rb") as f:
                doc = tomllib.load(f)
        except tomllib.TOMLDecodeError as exc:
            raise ConfigError(f"{path}: invalid TOML: {exc}") from exc

        known = {f_.name for f_ in Config.__dataclass_fields__.values()}
        unknown = set(doc) - known
        if unknown:
            raise ConfigError(
                f"{path}: unknown config keys: {', '.join(sorted(unknown))}")

        cfg = Config(**doc)
        if not (0.0 <= cfg.repack_threshold <= 1.0):
            raise ConfigError("repack_threshold must be in [0, 1]")
        if cfg.pack_size < 1024 * 1024:
            raise ConfigError("pack_size below 1 MiB is pathological")
        return cfg

    # -- passphrase resolution (module docstring order) ---------------------

    def resolve_passphrase(self, *, confirm: bool = False) -> str:
        env = os.environ.get(ENV_PASSPHRASE)
        if env is not None:
            if not env:
                raise ConfigError(f"${ENV_PASSPHRASE} is set but empty")
            return env

        if self.passphrase_file:
            p = Path(self.passphrase_file).expanduser()
            try:
                mode = stat.S_IMODE(os.stat(p).st_mode)
            except OSError as exc:
                raise ConfigError(f"passphrase_file: {exc}") from exc
            if mode & 0o077:
                raise ConfigError(
                    f"{p}: passphrase file is group/world-accessible "
                    f"(mode {mode:o}) — chmod 600 it")
            content = p.read_text().strip()
            if not content:
                raise ConfigError(f"{p}: passphrase file is empty")
            return content

        if not sys.stdin.isatty():
            raise ConfigError(
                "no passphrase source: set $CASBACKUP_PASSPHRASE or "
                "passphrase_file in config (stdin is not a TTY, cannot prompt)")
        import getpass
        pw = getpass.getpass("repository passphrase: ")
        if confirm:
            if getpass.getpass("confirm passphrase: ") != pw:
                raise ConfigError("passphrases do not match")
        if not pw:
            raise ConfigError("empty passphrase refused")
        return pw

    # -- excludes -> predicate (scanner.py contract) --------------------------

    def exclude_fn(self):
        """Compile exclude globs into the scanner's predicate.
        fnmatch semantics against the relative path; a pattern
        matching a directory prunes its whole subtree (scanner skips
        before descending)."""
        if not self.excludes:
            return None
        import fnmatch
        patterns = list(self.excludes)

        def fn(rel_path: str) -> bool:
            return any(fnmatch.fnmatch(rel_path, p)
                       or fnmatch.fnmatch(rel_path.rsplit("/", 1)[-1], p)
                       for p in patterns)
        return fn
