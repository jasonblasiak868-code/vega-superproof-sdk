"""signature.py - algorithm-tagged signatures over the top root. Ed25519 is built in. Post-quantum algorithms
(ML-DSA, SLH-DSA) are interfaces that fail closed until a vetted implementation is registered; the SDK does not
fake a post-quantum signature and does not silently substitute Ed25519 for one."""
import os
import sys

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from vega_superproof.seal.errors import SignatureUnavailable  # noqa: E402

_BACKENDS = {}  # alg -> object with sign(private, msg)->bytes, verify(public, msg, sig)->bool


def register(alg: str, backend, replace: bool = False):
    """Register a signature backend once. A second registration for the same algorithm is refused unless replace=True, so code that merely imports this module cannot quietly
    swap in a verifier that always says yes."""
    if not (callable(getattr(backend, "sign", None)) and callable(getattr(backend, "verify", None))):
        raise TypeError("backend needs sign() and verify()")
    if not isinstance(alg, str) or not alg or alg == "ed25519":
        raise ValueError("invalid algorithm name")
    if alg in _BACKENDS and _BACKENDS[alg] is not backend and not replace:
        raise ValueError(f"{alg} already has a registered backend; pass replace=True deliberately to change it")
    _BACKENDS[alg] = backend


def supported():
    return ["ed25519"] + sorted(_BACKENDS)


def new_ed25519():
    sk = Ed25519PrivateKey.generate()
    return sk, sk.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def sign_root(private, root_hex: str, alg: str = "ed25519", public: bytes = None) -> dict:
    msg = bytes.fromhex(root_hex)
    if alg == "ed25519":
        sig = private.sign(msg)
    elif alg in _BACKENDS:
        sig = _BACKENDS[alg].sign(private, msg)
    else:
        raise SignatureUnavailable(f"{alg} has no implementation registered; refusing to substitute another")
    return {"alg": alg, "signature": bytes(sig).hex(), "public": (public.hex() if public else None)}


def verify_root(sig: dict, root_hex: str, public: bytes, expected_alg: str = None) -> bool:
    """expected_alg: the algorithm the CONFIGURATION says was used. The algorithm named inside the signature object comes from the document being checked, so trusting it
    alone would let an attacker pick the weakest registered verifier."""
    msg, raw = bytes.fromhex(root_hex), bytes.fromhex(sig["signature"])
    alg = sig.get("alg")
    if expected_alg is not None and alg != expected_alg:
        return False
    if alg == "ed25519":
        try:
            Ed25519PublicKey.from_public_bytes(public).verify(raw, msg)
            return True
        except (InvalidSignature, ValueError):
            return False
    if alg in _BACKENDS:
        return bool(_BACKENDS[alg].verify(public, msg, raw))
    raise SignatureUnavailable(f"{alg} has no implementation registered")
