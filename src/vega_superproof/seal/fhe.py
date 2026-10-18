"""fhe.py - fully homomorphic computation, ONLY where computation on locked data is required (IV.8.8b).

The SDK carries the interface and the refusal, not a homemade FHE scheme. If no backend is registered, any
request for locked compute raises FHEUnavailable: it never falls back to computing on plaintext. A backend must
expose evaluate(operation: str, ciphertexts: list) -> object.

Note FHE hides the data; it does not prove the computation ran correctly. Pair it with an execution proof
(see cards/server_card.py: verify_execution_proof)."""


class FHEUnavailable(Exception):
    """Locked compute was requested and no FHE backend is registered."""


_BACKEND = None


def register_backend(backend, replace: bool = False):
    global _BACKEND
    if not callable(getattr(backend, "evaluate", None)):
        raise TypeError("backend needs evaluate(operation, ciphertexts)")
    if _BACKEND is not None and _BACKEND is not backend and not replace:
        raise ValueError("an FHE backend is already registered; pass replace=True deliberately to change it")
    _BACKEND = backend


def available() -> bool:
    return _BACKEND is not None


def locked_compute(operation: str, ciphertexts: list):
    if _BACKEND is None:
        raise FHEUnavailable("no FHE backend registered; refusing to compute on plaintext")
    return _BACKEND.evaluate(operation, ciphertexts)
