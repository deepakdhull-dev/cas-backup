from __future__ import annotations
from struct
from pathlib import Path
from typing import Iterable, Iterator
import lmdb
from . import hasher
from .packfile import PackEntry

_VALUE=struct.Struct(">32sQI")
VALUE_SIZE:int=_VALUE.size

DEFAULT_MAP_SIZE:int=4*1024*1024*1024

class IndexError_(Exception):

class ChunkIndex:
    def __init__(self,path:str|Path, map_size:int=DEFAULT_MAP_SIZE)->None:
        self._env=lmdb.open(str(path),map_size=map_size,sundir=True,max_dbs=0)

    def add_pack(self,pack_id:bytes,entries:Iterable[PackEntry])->None:
        try:
            with self._env.begin(write=True) as txn:
                for e in entries:
                    txn.put(e.chunk_id,_VALUE.pack(pack_id,e.offset,e.length))
        except lmdb.MapFullError as exc:
            raise IndexError_(
                "chunk index map size exhausted — raise index.map_size "
                "in the repository config and reopen"
            ) from exc

    def has(self,chunk_id:bytes)->bool:
        with self._env.begin() as txn:
            return txn.get(chunk_id) is not None

    def get(self,chunk_id:bytes)->tuple[bytes,PackEntry] | None:
        with self._env.begin() as txn:
            raw=txn.get(chunk_id)
        if raw is None:
            return None
        pack_id,offset,length=_VALUE.unpack(raw)
        return pack_id,PackEntry(chunk_id=bytes(chunk_id),offset=offset,length=length)

    def __len__(self)->int:
        with self._env.begin() as txn:
            return txn.stat()["entries"]

    def iter_all(self)->Iterator[tuple[bytes,bytes]]:
        with self._env.begin() as txn:
            for key,raw in txn.cursor():
                pack_id=_VALUE.unpack(raw)[0]
                yield bytes(key),pack_id

    def remove (self,chunk_ids:Iterable[bytes])->None:
        with self._env.begin(write=True) as txn:
            for cid in chunk_ids:
                txn.delete(cid)

    def clear(self) -> None:
        with self._env.begin(write=True) as txn:
            db = self._env.open_db(txn=txn)
            txn.drop(db, delete=False)

    def rebuild(self, backend, pack_ids: Iterable[bytes]) -> int:
        from .packfile import iter_entries   # local import: avoid cycle
        self.clear()
        count = 0
        for pack_id in pack_ids:
            entries = [e for e, _ in iter_entries(backend, pack_id)]
            self.add_pack(pack_id, entries)
            count += len(entries)
        return count

    def close(self) -> None:
        self._env.close()

    def __enter__(self) -> "ChunkIndex":
        return self

    def __exit__(self, *exc) -> None:
        self.close()


def _selfcheck() -> None:
    assert VALUE_SIZE == hasher.DIGEST_SIZE + 8 + 4


_selfcheck()
