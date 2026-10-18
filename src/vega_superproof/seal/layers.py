"""layers.py - the two cipher layers of the superproof.

  layer 1: AES-256-GCM        (key 1)   plaintext  -> c1
  layer 2: ChaCha20-Poly1305  (key 2)   c1         -> c2

Both are authenticated: any change to c2 is rejected on open. Every envelope names its algorithms (algorithm
tagging, IV.8.7) so a later release can add or retire an algorithm without guessing. Hashes of c1 and c2 are
proof of what was produced, not secrecy; the keys never appear in any record."""
import base64
import hashlib
import os

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305

ALG_1 = "aes-256-gcm"
ALG_2 = "chacha20-poly1305"
VERSION = 1


def generate_key() -> bytes:
    """The only sanctioned way to make a layer key: 32 bytes from the operating system's random source. (key_id() is a hash of the key and is recorded in the chain:
    for a random 256-bit key that is safe; for a key derived from a passphrase it would let anyone test guesses offline. Never derive these keys from a passphrase directly.)"""
    return os.urandom(32)


def _check_key(k: bytes, name: str):
    if not isinstance(k, (bytes, bytearray)) or len(k) != 32:
        raise ValueError(f"{name} must be 32 bytes")
    if len(set(bytes(k))) < 8:
        raise ValueError(f"{name} looks like a patterned key, not random bytes: use generate_key()")


def validate_keys(key1: bytes, key2: bytes) -> None:
    """Checked at the START of a seal, before any record is written, so a refused seal leaves no orphan entries."""
    _check_key(key1, "key1")
    _check_key(key2, "key2")
    if bytes(key1) == bytes(key2):
        raise ValueError("key1 and key2 must differ")


def seal_layers(plaintext: bytes, key1: bytes, key2: bytes, aad: bytes = b"") -> dict:
    _check_key(key1, "key1")
    _check_key(key2, "key2")
    if bytes(key1) == bytes(key2):
        raise ValueError("key1 and key2 must differ")
    n1, n2 = os.urandom(12), os.urandom(12)
    c1 = AESGCM(bytes(key1)).encrypt(n1, plaintext, aad)
    c2 = ChaCha20Poly1305(bytes(key2)).encrypt(n2, c1, aad)
    return {
        "version": VERSION, "alg1": ALG_1, "alg2": ALG_2,
        "n1": n1.hex(), "n2": n2.hex(),
        "ct_b64": base64.b64encode(c2).decode("ascii"),
        "aad_sha256": hashlib.sha256(aad).hexdigest(),
        "c1_sha256": hashlib.sha256(c1).hexdigest(),
        "c2_sha256": hashlib.sha256(c2).hexdigest(),
    }


def ciphertext_digest_ok(env: dict) -> bool:
    """Recompute the digest of the ciphertext actually present and compare it with the one the envelope claims."""
    try:
        return hashlib.sha256(base64.b64decode(env["ct_b64"], validate=True)).hexdigest() == env["c2_sha256"]
    except (KeyError, ValueError, TypeError):
        return False


def open_layers(env: dict, key1: bytes, key2: bytes, aad: bytes = b"") -> bytes:
    """Every malformed-envelope problem is a ValueError (never KeyError, binascii.Error or a bare cryptography error)."""
    try:
        if not isinstance(env, dict) or (env.get("alg1"), env.get("alg2"), env.get("version")) != (ALG_1, ALG_2, VERSION):
            raise ValueError("unknown algorithm tags: refusing to guess")
        if hashlib.sha256(aad).hexdigest() != env["aad_sha256"]:
            raise ValueError("aad does not match the sealed envelope")
        if not ciphertext_digest_ok(env):
            raise ValueError("ciphertext does not match its recorded digest")
        c2 = base64.b64decode(env["ct_b64"], validate=True)
        n1, n2 = bytes.fromhex(env["n1"]), bytes.fromhex(env["n2"])
        if len(n1) != 12 or len(n2) != 12:
            raise ValueError("nonces must be 12 bytes")
        c1 = ChaCha20Poly1305(bytes(key2)).decrypt(n2, c2, aad)
        return AESGCM(bytes(key1)).decrypt(n1, c1, aad)
    except (ValueError, InvalidTag):               # InvalidTag = wrong key or tampering: a clear cryptographic failure, kept as its own type
        raise
    except Exception as exc:                      # KeyError (missing field), TypeError (wrong field type)
        raise ValueError(f"cannot open: {type(exc).__name__}") from exc
