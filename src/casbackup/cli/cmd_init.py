"""init — create a repository. Prompts twice for the passphrase (typo
in a passphrase you set = repository you can never open; the confirm
prompt is the only guard)."""

import click

from ..repo import init_repository


def register(cli):
    @cli.command()
    @click.pass_obj
    def init(ctx):
        """Initialize a new repository."""
        pw = ctx.cfg.resolve_passphrase(confirm=True)
        init_repository(ctx.repo_path, pw, cfg=ctx.cfg)
        click.echo(f"repository initialized: {ctx.repo_path}")
        click.echo("passphrase is UNRECOVERABLE if lost — store it now.")
