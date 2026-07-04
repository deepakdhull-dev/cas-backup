from __future__ import annotations

import sys

import click

from ..config import Config, ConfigError
from ..repo import Repository, RepositoryError


class Ctx:
    """Shared CLI state: parsed config + repo path resolution."""

    def __init__(self, config_path: str | None, repo_flag: str | None):
        self.cfg = Config.load(config_path)
        self.repo_path = repo_flag or self.cfg.repository
        if not self.repo_path:
            raise ConfigError(
                "no repository: pass --repo or set `repository` in config"
            )


def open_repo(ctx: Ctx, *, confirm_passphrase: bool = False) -> Repository:
    pw = ctx.cfg.resolve_passphrase(confirm=confirm_passphrase)
    return Repository(ctx.repo_path, pw, cfg=ctx.cfg)


@click.group()
@click.option("--repo", "-r", help="repository path (overrides config)")
@click.option("--config", "-c", "config_path", help="config file path")
@click.pass_context
def cli(ctx: click.Context, repo: str | None, config_path: str | None) -> None:
    """casbackup — content-addressable incremental backups."""
    try:
        ctx.obj = Ctx(config_path, repo)
    except ConfigError as exc:
        raise click.ClickException(str(exc))


def _register() -> None:
    from . import cmd_backup, cmd_check, cmd_init, cmd_list, cmd_prune, cmd_restore

    for mod in (cmd_init, cmd_backup, cmd_restore, cmd_list, cmd_check, cmd_prune):
        mod.register(cli)


_register()


def main() -> None:
    try:
        cli(standalone_mode=False)
    except click.ClickException as exc:
        exc.show()
        sys.exit(1)
    except click.Abort:
        sys.exit(1)
    except (ConfigError, RepositoryError) as exc:
        click.echo(f"error: {exc}", err=True)
        sys.exit(1)


if __name__ == "__main__":
    main()
