from  __future__ import annotations
from abc import ABC, abstractmethod
from typing import Iterator
class BackendError(Exception):

class BlolNotFoundError(BackendError):

class Backend(ABC):
    @abstractmethod
    def put_bytes(self,name:str,data:bytes)->None:

    @abstractmethod
    def put_file(self,name:str,locale_path:str)->None:

    @abstractmethod
    def get_bytes(self,name:str)->bytes:

    @abstractmethod
    def get_range(self,name:str,offset:int,length:int)->bytes:

    @abstractmethod
    def exists(self,name:str)->bool:

    @abstractmethod
    def size(self,name:str)->int:

    @abstractmethod
    def list(self,prefix:str)->Iterator[str]:

    @abstractmethod
    def delete(self,name:str)->None:
