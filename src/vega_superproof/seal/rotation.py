"""rotation.py - UPDATING encryption for sealed records: change the keys without losing the seal's history.

  KeyRatchet(root_secret)   epoch keys that only move forward: advance() derives the next epoch's pair of layer keys and drops the old one, so a key stolen later
                            cannot open what was sealed under an earlier epoch (forward secrecy). Python cannot truly wipe memory; the old key is released, not scrubbed:
                            for a hard guarantee keep the ratchet in a hardware module.
  reseal(...)               opens a seal with the old keys and seals the same capsule under new keys (and, if asked, another preset), writing a SEAL_ROTATED record
                            that links the old top root to the new one. The old seal stays valid as history; only the new one should be kept online.
The homomorphic layer rotates its own key (lwe.KeyHolder.rotate), also epoch by epoch."""
import hashlib
import hmac

from vega_superproof.seal import superproof
from vega_superproof.seal.errors import SealError
from vega_superproof.seal.lineage import key_id


class KeyRatchet:
    def __init__(self, root_secret: bytes):
        if not isinstance(root_secret, (bytes, bytearray)) or len(root_secret) != 32 or len(set(bytes(root_secret))) < 8:
            raise ValueError("root_secret is 32 random bytes")
        self._k = bytes(root_secret)
        self.epoch = 0

    def current(self):
        """-> (key1, key2) for this epoch."""
        e = self.epoch.to_bytes(8, "big")
        return (hmac.new(self._k, b"VEGA-LAYER-1|" + e, hashlib.sha256).digest(), hmac.new(self._k, b"VEGA-LAYER-2|" + e, hashlib.sha256).digest())

    def advance(self) -> int:
        self._k = hmac.new(self._k, b"VEGA-RATCHET|" + self.epoch.to_bytes(8, "big"), hashlib.sha256).digest()
        self.epoch += 1
        return self.epoch


def reseal(sealed: dict, old_key1: bytes, old_key2: bytes, new_key1: bytes, new_key2: bytes, signing_key, signing_public: bytes, dag, ledger, preset: str = None) -> dict:
    if (bytes(new_key1), bytes(new_key2)) == (bytes(old_key1), bytes(old_key2)):
        raise SealError("the new keys are the old keys: nothing was rotated")
    c = superproof.open_seal(sealed, old_key1, old_key2)
    out = superproof.seal(c, new_key1, new_key2, signing_key, signing_public, dag, ledger, preset or sealed["preset"]["name"])
    dag.record("SEAL_ROTATED", {"old_top_root": sealed["top_root"], "new_top_root": out["top_root"], "old_k1_id": key_id(old_key1), "new_k1_id": key_id(new_key1)},
               parents=[out["audit_entry"]])
    return out
