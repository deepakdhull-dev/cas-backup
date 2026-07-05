"""Chunk encryption (decision 11: AES-256-GCM).

WHAT PROBLEM ENCRYPTION SOLVES HERE
===================================
The repository may sit on an untrusted disk, a stolen laptop, or (once
remote backends exist, decision 14) someone else's server. Encryption
at rest means possession of the repository files alone reveals nothing
about the backed-up content.

WHY AEAD, NOT PLAIN ENCRYPTION
==============================
AES-256-GCM is an AEAD: Authenticated Encryption with Associated Data.
It provides two guarantees simultaneously:

1. CONFIDENTIALITY — ciphertext reveals nothing about plaintext
   without the key.
2. AUTHENTICITY — decryption *fails loudly* if the ciphertext was
   modified by even one bit. GCM appends a 16-byte authentication tag
   computed over the ciphertext; decryption recomputes and compares
   it. Without this, an attacker who can write to the repository could
   flip ciphertext bits to flip plaintext bits (AES-CTR, which GCM is
   built on, has this malleability) and corrupt restored files in
   controlled ways. Plain AES-CBC/CTR without authentication is a
   well-known design error; AEAD is the modern baseline.

The "associated data" (AAD) feature lets us cryptographically bind
metadata to a ciphertext without encrypting it. We bind the chunk id:
decrypting chunk X's blob while claiming it is chunk Y fails
authentication. This kills chunk-swapping attacks — an attacker
rearranging valid encrypted blobs inside a pack file — which mere
per-blob encryption would not detect until the (unencrypted-world)
hash check much later. Defense in depth, priced at zero extra bytes.

THE NONCE: THE ONE RULE THAT MUST NEVER BREAK
=============================================
GCM requires a 96-bit nonce ("number used once") per encryption. The
absolute rule: NEVER encrypt two different messages with the same
(key, nonce) pair. A single reuse leaks the XOR of the two plaintexts
AND enough information to forge authentication tags — catastrophic,
not theoretical.

Strategy chosen: 12 random bytes from os.urandom per encryption,
stored alongside the ciphertext. Collision probability over N
encryptions is ~N^2 / 2^97 (birthday bound). At one billion chunks:
~(2^30)^2 / 2^97 = 2^-37 ≈ one in 10^11. Acceptable. The alternative
(a persistent counter) removes even that risk but adds crash-safe
counter state — complexity we do not take on in v1.

CONSEQUENCE FOR DEDUPLICATION — READ THIS CAREFULLY
===================================================
Random nonces mean encrypting the same chunk twice yields different
ciphertexts. This does NOT hurt our dedup: dedup happens BEFORE
encryption, keyed on the plaintext chunk id (hasher.py). A chunk
already in the index is never re-encrypted or re-stored at all. The
thing we lose is the ability for the *storage server* to dedup across
users/repositories — irrelevant for a single-repo design. (Convergent
encryption would allow that, at the cost of confirmation-of-file
attacks; rejected in decision 11.)

WHAT THE KEY IS
===============
One 32-byte (256-bit) repository-wide key, generated randomly at
`init`. All chunks and manifests encrypt under it.

The key itself must be stored somewhere the user can retrieve —
protected by a passphrase. We derive a Key-Encryption-Key (KEK) from
the passphrase with scrypt, then wrap (encrypt) the repository key
with the KEK using the same AES-256-GCM. Why this indirection instead
of deriving the data key from the passphrase directly? Passphrase
changes: re-wrapping one 32-byte key is instant; re-encrypting every
chunk in the repository is not.

scrypt parameters (n=2^15, r=8, p=1): deliberately slow (~100 ms) and
memory-hard (~32 MiB) to make offline passphrase brute-force expensive.
Normal hashes (SHA-256) are the WRONG tool for passphrases precisely
because they are fast.

PENDING DECISION (flagged, not taken): where the wrapped key lives
(inside the repository directory vs a separate keyfile path) and
whether passphrase-less operation is allowed. Belongs to repo.py /
config.py stage. This module only provides the primitives.

WIRE FORMAT (this module's on-disk contract)
============================================
    sealed blob = nonce (12 bytes) || ciphertext+tag (len(pt) + 16)

Total overhead: 28 bytes per chunk. At 64 KiB average chunk size that
is 0.04% — negligible.
"""

from __future__ import annotations

import os

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

KEY_SIZE: int = 32     # AES-256 => 32-byte key
NONCE_SIZE: int = 12   # 96-bit nonce, GCM's designed-for size
TAG_SIZE: int = 16     # GCM auth tag, appended to ciphertext by the lib

# scrypt cost parameters. Format-relevant: changing them changes how
# an existing wrapped key must be unwrapped, so they are stored in the
# repository's key header (repo.py stage) rather than assumed. These
# are the defaults for NEW repositories.
SCRYPT_N: int = 2 ** 15   # CPU/memory cost (32768 iterations-ish)
SCRYPT_R: int = 8         # block size — with n, sets ~32 MiB memory
SCRYPT_P: int = 1         # parallelism
SALT_SIZE: int = 16


class DecryptionError(Exception):
    """Raised when authentication fails during decryption.

    Means one of: wrong key, corrupted ciphertext, tampered ciphertext,
    or blob presented under the wrong chunk id (AAD mismatch). The
    cryptography library cannot distinguish these cases — by design;
    distinguishing them would leak information to attackers.
    """


def generate_key() -> bytes:
    """Generate a fresh repository master key.

    os.urandom is the kernel CSPRNG — the correct source. NEVER the
    `random` module: it is a deterministic PRNG (Mersenne Twister),
    predictable from its outputs, fine for the gear table in
    chunker.py (where determinism is REQUIRED), fatal for keys.
    """
    return os.urandom(KEY_SIZE)


def encrypt(key: bytes, plaintext: bytes, aad: bytes = b"") -> bytes:
    """Seal a blob under the repository key.

    Args:
        key:       32-byte repository key.
        plaintext: compress.py output (tag byte + payload).
        aad:       associated data to bind — callers pass the chunk id.
                   Authenticated, NOT encrypted, NOT stored here (the
                   reader is expected to know it independently: it
                   looked the blob up BY chunk id).

    Returns:
        nonce || ciphertext+tag  (len(plaintext) + 28 bytes).
    """
    if len(key) != KEY_SIZE:
        raise ValueError(f"key must be {KEY_SIZE} bytes, got {len(key)}")
    nonce = os.urandom(NONCE_SIZE)
    ct = AESGCM(key).encrypt(nonce, plaintext, aad)
    return nonce + ct


def decrypt(key: bytes, blob: bytes, aad: bytes = b"") -> bytes:
    """Open a sealed blob. Verifies integrity before returning anything.

    GCM decrypts and authenticates in one pass; if the tag does not
    verify, the library raises and NO plaintext is released. There is
    no such thing as "decrypted but unverified" output from this
    function — that property is what makes verify-on-read (decision 17)
    partially free: every restore read is integrity-checked here even
    before the chunk-id re-hash check.

    Raises:
        DecryptionError: authentication failed (see class docstring).
        ValueError: blob structurally too short to contain nonce+tag.
    """
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


# ---------------------------------------------------------------------------
# Passphrase-based key wrapping (KEK indirection — see module docstring)
# ---------------------------------------------------------------------------

def derive_kek(passphrase: str, salt: bytes,
               n: int = SCRYPT_N, r: int = SCRYPT_R,
               p: int = SCRYPT_P) -> bytes:
    """Derive the key-encryption-key from a user passphrase via scrypt.

    The salt (random, stored in the clear next to the wrapped key)
    ensures two repositories with the same passphrase still have
    different KEKs, and defeats precomputed (rainbow-table) attacks.
    """
    kdf = Scrypt(salt=salt, length=KEY_SIZE, n=n, r=r, p=p)
    return kdf.derive(passphrase.encode("utf-8"))


def wrap_key(master_key: bytes, passphrase: str) -> tuple[bytes, bytes]:
    """Encrypt the repository master key under a passphrase.

    Returns:
        (salt, wrapped) — both stored in the repository key header.
        `wrapped` is a normal sealed blob (nonce || ct+tag) under the
        derived KEK, with AAD b"casbackup-key-v1" so a wrapped key can
        never be confused with (or substituted by) an ordinary chunk
        blob.
    """
    salt = os.urandom(SALT_SIZE)
    kek = derive_kek(passphrase, salt)
    wrapped = encrypt(kek, master_key, aad=b"casbackup-key-v1")
    return salt, wrapped


def unwrap_key(salt: bytes, wrapped: bytes, passphrase: str,
               n: int = SCRYPT_N, r: int = SCRYPT_R,
               p: int = SCRYPT_P) -> bytes:
    """Recover the master key. Wrong passphrase surfaces as
    DecryptionError — GCM's auth tag doubles as the passphrase check;
    no separate verifier value needs storing.
    """
    kek = derive_kek(passphrase, salt, n=n, r=r, p=p)
    return decrypt(kek, wrapped, aad=b"casbackup-key-v1")
