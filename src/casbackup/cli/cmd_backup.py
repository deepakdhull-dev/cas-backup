"""backup — snapshot a source directory."""

import click

from .main import open_repo


def register(cli):
    @cli.command()
    @click.argument("source", type=click.Path(exists=True, file_okay=False))
    @click.pass_obj
    def backup(ctx, source):
        """Create a snapshot of SOURCE."""
        with open_repo(ctx) as repo:
            snap, rep = repo.backup(source)
        click.echo(f"snapshot {snap.id}")
        click.echo(f"  files={rep.files} dirs={rep.dirs} "
                   f"symlinks={rep.symlinks}")
        click.echo(f"  read {rep.bytes_read:,} bytes, "
                   f"{rep.chunks_new} new chunks stored")
        if rep.skipped:
            click.echo(f"  SKIPPED {len(rep.skipped)} entries:", err=True)
            for path, why in rep.skipped:
                click.echo(f"    {path}: {why}", err=True)
