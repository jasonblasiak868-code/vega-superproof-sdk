"""scrambler.py - key rotation. HONEST LABEL: this is KEY RE-WRAP (envelope encryption). The data key is wrapped
under a key-encryption key; rotation unwraps with the old KEK and wraps under the new one, without touching the
ciphertext. It is not an updatable-encryption scheme over the ciphertext itself, and it is not homomorphic.

Two rules, both enforced here:
  - the card will not rotate without a FRESH, minted, single-use commitment (require_commitment)
  - every rotation is committed to the chain and the old key id is retired (commit_rotation)"""
import hashlib
import os
import sys
import threading
import time

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from vega_superproof.seal.lineage import key_id  # noqa: E402

ROTATE_ACTION = "rotate_keys"
_GUARD = threading.Lock()


def _lock_for(dag):
    """One lock per DAG object: 'is this commitment / this key already used?' and 'record the rotation' are one step, so two rotations can never both pass."""
    with _GUARD:
        lk = getattr(dag, "_vega_rotation_lock", None)
        if lk is None:
            lk = threading.RLock()
            dag._vega_rotation_lock = lk
        return lk


class RotationRefused(Exception):
    pass


def wrap(dek: bytes, kek: bytes, aad: bytes = b"vega-wrap-v1") -> bytes:
    n = os.urandom(12)
    return n + AESGCM(bytes(kek)).encrypt(n, bytes(dek), aad)


def unwrap(wrapped: bytes, kek: bytes, aad: bytes = b"vega-wrap-v1") -> bytes:
    return AESGCM(bytes(kek)).decrypt(wrapped[:12], wrapped[12:], aad)


def require_commitment(ledger, dag, commitment: dict, action: str = ROTATE_ACTION) -> str:
    """The commitment must be for this action, unexpired, really minted, and never used for a rotation before."""
    if not isinstance(commitment, dict):
        raise RotationRefused("a commitment is an object")
    if commitment.get("action") != action:
        raise RotationRefused(f"commitment is for {commitment.get('action')!r}, not {action!r}")
    try:
        expired = int(commitment.get("expiry", 0)) <= int(time.time())
    except (TypeError, ValueError, OverflowError):
        raise RotationRefused("the commitment's expiry is not a whole number") from None
    if expired:
        raise RotationRefused("commitment expired")
    if not ledger.verify(commitment):
        raise RotationRefused("commitment is not in the ledger")
    from vega_custody.ledger.ledger import leaf_of
    leaf = leaf_of(commitment)
    if any(e["kind"] == "ROTATION" and e["payload"].get("commitment_leaf") == leaf for e in dag.content.entries()):
        raise RotationRefused("commitment already used for a rotation (single use)")
    return leaf


def commit_rotation(dag, old_kid: str, new_kid: str, commitment_leaf: str, parents=None) -> dict:
    """Record the rotation and retire the old key id. Ids only, never key material."""
    retired = {e["payload"]["old_key_id"] for e in dag.content.entries() if e["kind"] == "ROTATION"}
    if old_kid in retired:
        raise RotationRefused("old key id was already retired")
    return dag.record("ROTATION", {"old_key_id": old_kid, "new_key_id": new_kid, "commitment_leaf": commitment_leaf,
                                   "method": "key-rewrap", "retired": [old_kid]}, parents=parents)


def rotate(wrapped_dek: bytes, old_kek: bytes, new_kek: bytes, ledger, dag, commitment: dict) -> dict:
    with _lock_for(dag):
        leaf = require_commitment(ledger, dag, commitment)
        dek = unwrap(wrapped_dek, old_kek)
        new_wrapped = wrap(dek, new_kek)
        entry = commit_rotation(dag, key_id(old_kek), key_id(new_kek), leaf)
    return {"wrapped": new_wrapped, "entry": entry["entry_hash"], "old_key_id": key_id(old_kek),
            "new_key_id": key_id(new_kek)}
