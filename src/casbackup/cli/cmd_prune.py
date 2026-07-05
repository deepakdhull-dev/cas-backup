"""prune — forget snapshots and/or reclaim unreferenced storage."""

import click

from .main import open_repo


def register(cli):
    @cli.command()
    @click.option("--forget", "refs", multiple=True,
                  help="snapshot ref(s) to delete before collecting")
    @click.pass_obj
    def prune(ctx, refs):
        """Garbage-collect unreferenced chunks (mark-and-sweep)."""
        with open_repo(ctx) as repo:
            for ref in refs:
                sid = repo.forget(ref)
                click.echo(f"forgot snapshot {sid}")
            st = repo.prune()
        click.echo(f"chunks: {st.chunks_total} total, {st.chunks_dead} dead")
        click.echo(f"packs: {st.packs_deleted} deleted, "
                   f"{st.packs_repacked} repacked, {st.packs_kept} kept, "
                   f"{st.orphan_packs_deleted} orphans removed")
        click.echo(f"reclaimed {st.bytes_reclaimed:,} bytes")
        for note in st.notes:
            click.echo(f"  {note}")
