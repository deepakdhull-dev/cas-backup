"""check — verify repository health. Read-only. Exit 3 on problems."""

import sys

import click

from .main import open_repo


def register(cli):
    @cli.command()
    @click.option("--read-data", is_flag=True,
                  help="deep scan: read and verify every stored chunk")
    @click.option("--rebuild-index", is_flag=True,
                  help="repair: reconstruct the chunk index from packs")
    @click.pass_obj
    def check(ctx, read_data, rebuild_index):
        """Verify repository integrity."""
        with open_repo(ctx) as repo:
            if rebuild_index:
                n = repo.rebuild_index()
                click.echo(f"index rebuilt: {n} entries")
            rep = repo.check(read_data=read_data)
        click.echo(f"snapshots={rep.snapshots_checked} "
                   f"files={rep.files_seen} "
                   f"chunks_referenced={rep.chunks_referenced} "
                   f"packs={rep.packs_checked}"
                   + (f" chunks_read={rep.chunks_read}" if read_data else ""))
        for name, items in (("missing chunks", rep.chunks_missing),
                            ("corrupt chunks", rep.chunks_corrupt),
                            ("pack problems", rep.pack_problems),
                            ("errors", rep.errors)):
            for item in items:
                click.echo(f"  {name}: {item}", err=True)
        if rep.orphan_packs:
            click.echo(f"  orphan packs (run prune): "
                       f"{len(rep.orphan_packs)}", err=True)
        if not rep.ok:
            click.echo("REPOSITORY HAS PROBLEMS", err=True)
            sys.exit(3)
        click.echo("repository ok")
