import datetime

import click

from ..backup import walk_tree
from .main import open_repo


def register(cli):
    @cli.command(name="list")
    @click.argument("ref", required=False)
    @click.pass_obj
    def list_(ctx, ref):
        """List snapshots; with REF, list that snapshot's contents."""
        with open_repo(ctx) as repo:
            if ref is None:
                snaps = repo.snapshots()
                if not snaps:
                    click.echo("no snapshots")
                    return
                for s in snaps:
                    ts = datetime.datetime.fromtimestamp(s.created)
                    st = s.stats
                    click.echo(
                        f"{s.id}  {ts:%Y-%m-%d %H:%M:%S}  "
                        f"{s.source_path}  "
                        f"({st.get('files', '?')} files, "
                        f"{st.get('bytes_read', 0):,} bytes)"
                    )
            else:
                snap = repo.resolve(ref)
                for path, entry in walk_tree(repo.store, snap.root_tree):
                    suffix = "/" if entry.meta.type == "dir" else ""
                    click.echo(f"{path}{suffix}")
