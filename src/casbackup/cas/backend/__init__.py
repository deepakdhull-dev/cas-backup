"""Storage backends. Import Backend/errors from .base; concrete
implementations by name (.local.LocalBackend). New backends (S3, SFTP)
register here as they materialize — decision 14's extension point."""

from .base import Backend, BackendError, BlobNotFound
from .local import LocalBackend

__all__ = ["Backend", "BackendError", "BlobNotFound", "LocalBackend"]
