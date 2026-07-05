"""restore — full snapshot or single path. Exit 3 if any entry failed
(partial restores must not look like success to scripts)."""

import sys

import click

from .main import open_repo


def register(cli):
    @cli.command()
    @click.argument("ref")
    @click.argument("target", type=click.Path())
    @click.option("--path", "-p", help="restore only this path within the snapshot")
    @click.option("--force", is_flag=True, help="overwrite existing targets")
    @click.pass_obj
    def restore(ctx, ref, target, path, force):
        """Restore snapshot REF (id, prefix, or 'latest') into TARGET."""
        with open_repo(ctx) as repo:
            rep = repo.restore(ref, target, path=path, force=force)
        click.echo(f"restored files={rep.files} dirs={rep.dirs} "
                   f"symlinks={rep.symlinks} bytes={rep.bytes_written:,}")
        for w in rep.warnings:
            click.echo(f"  warning: {w}", err=True)
        if rep.failed:
            click.echo(f"  FAILED {len(rep.failed)} entries:", err=True)
            for p, why in rep.failed:
                click.echo(f"    {p}: {why}", err=True)
            sys.exit(3)
