from __future__ import annotations
import os
from cryptography.exceptions import InvavalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazman.primitives.scrypt import Scrypt

KEY_SIZE:int=32
NONCE_SIZE:int=12
TAG_SIZE:int=16

SCRYPT_N:int=2**15
SCRYPT_R:int=8
SCRYPT_P:int=1
SALT_SIZE:int=16

class DecryptionError(Exception):

def generate_key()->bytes:
    return os.urandom(KEY_SIZE)

def encrypt(key:bytes,plaintext:bytes,aad:bytes=b"")->bytes:
    if len(key)!=KEY_SIZE:
        raise ValueError(f"key must be {KEY_SIZE} bytes, got {len(key)}")
    nonce=os.urandom(NONCE_SIZE)
    ct=AESGCM(key).encrypt(nonce,plaintext,aad)
    return nonce+ct

def decrypt(key:bytes,blob:bytes,aad:bytes=b"")->bytes:
    if len(key) != KEY_SIZE:
        raise ValueError(f"key must be {KEY_SIZE} bytes, got {len(key)}")
    if len(blob) < NONCE_SIZE + TAG_SIZE:
        raise ValueError(
            f"sealed blob too short: {len(blob)} bytes < minimum "
            f"{NONCE_SIZE + TAG_SIZE}"
        )
    nonce, ct = blob[:NONCE_SIZE], blob[NONCE_SIZE:]
    try:
        return AESGCM(key).decrypt(nonce, ct, aad)
    except InvalidTag as exc:
        raise DecryptionError(
            "authentication failed: wrong key, corrupted data, or "
            "tampered repository"
        ) from exc

def derive_kek(passphrase: str, salt: bytes,
               n: int = SCRYPT_N, r: int = SCRYPT_R,
               p: int = SCRYPT_P) -> bytes:

    kdf = Scrypt(salt=salt, length=KEY_SIZE, n=n, r=r, p=p)
    return kdf.derive(passphrase.encode("utf-8"))

def wrap_key(master_key: bytes, passphrase: str) -> tuple[bytes, bytes]:
    salt = os.urandom(SALT_SIZE)
    kek = derive_kek(passphrase, salt)
    wrapped = encrypt(kek, master_key, aad=b"casbackup-key-v1")
    return salt, wrapped

def unwrap_key(salt: bytes, wrapped: bytes, passphrase: str,
               n: int = SCRYPT_N, r: int = SCRYPT_R,
               p: int = SCRYPT_P) -> bytes:
                   kek = derive_kek(passphrase, salt, n=n, r=r, p=p)
                   return decrypt(kek, wrapped, aad=b"casbackup-key-v1")
