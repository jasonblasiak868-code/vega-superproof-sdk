"""builtin.py - the three working backends for the seal's upper tiers. They are NOT registered automatically (a seal that asks for a tier nobody enabled still
fails closed); call enable_*() deliberately, once, at start-up.

  tier 1  PRIVACY        PrivacyBackend(secret)   a zero-knowledge proof (Schnorr signature of knowledge) that the sealer knows the secret behind a public point,
                                                  bound to this exact seal statement, without revealing the secret. Classical security (discrete log).
  tier 2  QUANTUM-PROOF  QuantumBackend()         every primitive in the seal is on the quantum-resistant list: 256-bit symmetric ciphers, SHA-256, a hash-based signature.
                                                  The proof is an attestation that the verifier re-checks against that list; the signature itself is hashsig.py.
  tier 3  LOCKED COMPUTE ComputeBackend(params_id, epoch, rotation_log)   tier 2 plus a binding to the homomorphic parameters and the encryption epoch (and the hash of
                                                  the rotation log), so a seal says WHICH generation of the updating encryption it belongs to.
What 'quantum-proof' means here: it rests only on hash functions and 256-bit symmetric keys, which a large quantum computer weakens but does not break (about 128-bit
security remains). It is not a claim about every attack and the code has had no independent review."""
import hashlib
import json

from vega_superproof.seal import ec, hashsig, proof_tier1, proof_tier2, proof_tier3, zk

QUANTUM_SAFE = {"layers": {"aes-256-gcm", "chacha20-poly1305"}, "hash": {"sha256"}, "signature": {hashsig.ALG}}


def _canon(o) -> bytes:
    return json.dumps(o, sort_keys=True, separators=(",", ":")).encode("utf-8")


def statement_digest(statement: dict) -> bytes:
    return hashlib.sha256(b"VEGA-SEAL-STATEMENT-1" + _canon(statement)).digest()


class PrivacyBackend:
    def __init__(self, secret: int):
        if isinstance(secret, bool) or not isinstance(secret, int) or not 1 <= secret < ec.N:
            raise ValueError("secret is a whole number from 1 to the group order")
        self._x = secret
        self.public = zk.public_of(secret)

    def prove(self, statement: dict) -> bytes:
        pr = zk.prove_knowledge(self._x, statement_digest(statement))
        return _canon({"public": self.public.hex(), "proof": pr})

    def verify(self, statement: dict, proof: bytes) -> bool:
        try:
            d = json.loads(bytes(proof).decode("utf-8"))
            return zk.verify_knowledge(bytes.fromhex(d["public"]), statement_digest(statement), d["proof"])
        except (ValueError, KeyError, TypeError):
            return False


class QuantumBackend:
    def _attest(self, statement):
        return {"layers": sorted(QUANTUM_SAFE["layers"]), "hash": "sha256", "signature": hashsig.ALG, "statement": statement_digest(statement).hex()}

    def prove(self, statement: dict) -> bytes:
        return _canon(self._attest(statement))

    def verify(self, statement: dict, proof: bytes) -> bool:
        try:
            d = json.loads(bytes(proof).decode("utf-8"))
            return (d == self._attest(statement) and set(d["layers"]) <= QUANTUM_SAFE["layers"] and d["hash"] in QUANTUM_SAFE["hash"]
                    and d["signature"] in QUANTUM_SAFE["signature"])
        except (ValueError, KeyError, TypeError):
            return False


class ComputeBackend(QuantumBackend):
    def __init__(self, params_id: str, epoch: int, rotation_log_sha256: str = "0" * 64):
        self.params_id, self.epoch, self.log = params_id, epoch, rotation_log_sha256

    def _attest(self, statement):
        d = super()._attest(statement)
        d.update({"he_params": self.params_id, "epoch": self.epoch, "rotation_log": self.log})
        return d

    def verify(self, statement: dict, proof: bytes) -> bool:
        try:
            d = json.loads(bytes(proof).decode("utf-8"))
            return (set(d["layers"]) <= QUANTUM_SAFE["layers"] and d["hash"] in QUANTUM_SAFE["hash"] and d["signature"] in QUANTUM_SAFE["signature"]
                    and d["statement"] == statement_digest(statement).hex() and isinstance(d["epoch"], int) and not isinstance(d["epoch"], bool)
                    and isinstance(d["he_params"], str) and isinstance(d["rotation_log"], str))
        except (ValueError, KeyError, TypeError):
            return False


def enable_privacy(secret: int, replace: bool = False) -> PrivacyBackend:
    b = PrivacyBackend(secret)
    proof_tier1.register(b, replace=replace)
    return b


def enable_quantum_proof(replace: bool = False) -> QuantumBackend:
    b = QuantumBackend()
    proof_tier2.register(b, replace=replace)
    hashsig.register(replace=replace)
    return b


def enable_locked_compute(params_id: str, epoch: int, rotation_log_sha256: str = "0" * 64, replace: bool = False) -> ComputeBackend:
    b = ComputeBackend(params_id, epoch, rotation_log_sha256)
    proof_tier3.register(b, replace=replace)
    hashsig.register(replace=replace)
    return b
