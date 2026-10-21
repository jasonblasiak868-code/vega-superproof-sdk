"""proof_tier1.py - Tier 1 (privacy: a zero-knowledge proof). The built-in backend is a Schnorr proof of knowledge (builtin.enable_privacy); a general-purpose SNARK prover
could be registered in the same slot, but none is shipped. The SDK ships the interface and refuses to run without a real prover: it
never fakes a proof and never silently falls back to a lower tier. Register a backend that exposes
prove(statement: dict) -> bytes and verify(statement: dict, proof: bytes) -> bool."""
import hashlib
import json
import os
import sys

from vega_superproof.seal.errors import TierUnavailable  # noqa: E402

TIER = 1
_BACKEND = None


def register(backend, replace: bool = False):
    """Register a prover once; replacing it must be deliberate (replace=True). Code that only imports this module cannot swap in a verifier that always says yes."""
    global _BACKEND
    if not (callable(getattr(backend, "prove", None)) and callable(getattr(backend, "verify", None))):
        raise TypeError("backend needs prove() and verify()")
    if _BACKEND is not None and _BACKEND is not backend and not replace:
        raise ValueError("a prover is already registered; pass replace=True deliberately to change it")
    _BACKEND = backend


def available() -> bool:
    return _BACKEND is not None


def require_prover():
    if _BACKEND is None:
        raise TierUnavailable("tier 1 (privacy) has no prover registered; refusing to downgrade")


def _canon(o) -> bytes:
    return json.dumps(o, sort_keys=True, separators=(",", ":")).encode("utf-8")


def prove(statement: dict) -> dict:
    require_prover()
    blob = _BACKEND.prove(statement)
    return {"tier": TIER, "statement": statement, "proof_hex": bytes(blob).hex(),
            "binding": hashlib.sha256(_canon({"tier": TIER, "statement": statement})).hexdigest()}


def verify(proof: dict) -> bool:
    require_prover()
    return proof.get("tier") == TIER and bool(_BACKEND.verify(proof["statement"], bytes.fromhex(proof["proof_hex"])))
