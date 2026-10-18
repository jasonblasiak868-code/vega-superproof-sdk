"""zk.py - the privacy tier: zero-knowledge proofs you can check without learning the secret. Plain Python on secp256k1 (see ec.py).

  commit(v)                          Pedersen commitment C = v*G + r*H: hides v (perfectly) and binds to it (as hard as the discrete log)
  prove_knowledge / verify_knowledge Schnorr proof that the prover knows x for the public point Y = x*G, bound to a message (a signature of knowledge)
  prove_range / verify_range         v is in [0, 2^bits), from a commitment, without revealing v (bit-by-bit commitments, each proved to hold 0 or 1 by an OR-proof)
  prove_at_least / verify_at_least   v >= T (and < T + 2^bits) without revealing v: the range proof on C - T*G. This is the 'income at least X' / 'balance at least X' building block.
  attest / verify_attestation        an issuer's Ed25519 signature over a commitment, so a verifier knows WHO vouches for the hidden number

Every proof is bound to a CONTEXT (bytes) through the Fiat-Shamir hash, so a proof made for one purpose does not verify for another.
HONEST LIMITS: classical security only (a large quantum computer breaks the discrete log); the quantum-proof tier is hash-based (disclosure.py, hashsig.py).
These proofs show the committed number is in range; whether the number is TRUE is the issuer's attestation, not the proof's. Plain Python, not constant-time,
no independent cryptographic review: do not protect real secrets with it before one."""
import secrets

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from vega_superproof.seal import ec

MAX_BITS = 64


class ZKRefused(ValueError):
    pass


def _scalar():
    while True:
        k = secrets.randbelow(ec.N)
        if k:
            return k


def _pt(b):
    try:
        p = ec.decode(bytes.fromhex(b) if isinstance(b, str) else b)
    except (ec.ECError, ValueError, TypeError) as exc:
        raise ZKRefused("not a valid point: %s" % exc) from exc
    return p


def _sc(h):
    try:
        v = int(h, 16) if isinstance(h, str) else None
    except ValueError:
        v = None
    if v is None or not 0 <= v < ec.N:
        raise ZKRefused("not a valid scalar")
    return v


def _hx(n):
    return "%064x" % n


def commit(value: int, blinding: int = None):
    """-> (commitment point bytes, blinding). Keep the blinding secret; it opens the commitment."""
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value < ec.N:
        raise ZKRefused("value must be a non-negative whole number")
    r = _scalar() if blinding is None else blinding
    return ec.encode(ec.add(ec.mul(value, ec.G), ec.mul(r, ec.H))), r


def opens_to(commitment: bytes, value: int, blinding: int) -> bool:
    try:
        return _pt(commitment) == ec.add(ec.mul(value, ec.G), ec.mul(blinding, ec.H))
    except ZKRefused:
        return False


# ---- Schnorr proof of knowledge ----------------------------------------------------------------------------
def public_of(x: int) -> bytes:
    return ec.encode(ec.mul(x, ec.G))


def prove_knowledge(x: int, message: bytes) -> dict:
    Y = ec.mul(x, ec.G)
    k = _scalar()
    R = ec.mul(k, ec.G)
    c = ec.hash_to_scalar(b"VEGA-SCHNORR-1", ec.encode(Y), ec.encode(R), message)
    return {"R": ec.encode(R).hex(), "s": _hx((k + c * x) % ec.N)}


def verify_knowledge(public: bytes, message: bytes, proof) -> bool:
    try:
        Y, R, s = _pt(public), _pt(proof["R"]), _sc(proof["s"])
        if Y is ec.INF or R is ec.INF:
            return False
        c = ec.hash_to_scalar(b"VEGA-SCHNORR-1", ec.encode(Y), ec.encode(R), message)
        return ec.mul(s, ec.G) == ec.add(R, ec.mul(c, Y))
    except (ZKRefused, KeyError, TypeError):
        return False


# ---- range proof ---------------------------------------------------------------------------------------------
def prove_range(value: int, blinding: int, bits: int, context: bytes = b"") -> dict:
    if not isinstance(bits, int) or isinstance(bits, bool) or not 1 <= bits <= MAX_BITS:
        raise ZKRefused("bits is 1 to %d" % MAX_BITS)
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value < (1 << bits):
        raise ZKRefused("the value is not in range: no honest proof exists")
    rs = [_scalar() for _ in range(bits - 1)]
    partial = sum((1 << i) * rs[i] for i in range(bits - 1)) % ec.N
    rs.append(((blinding - partial) * pow(1 << (bits - 1), -1, ec.N)) % ec.N)
    cs, proofs = [], []
    for i in range(bits):
        b = (value >> i) & 1
        Ci = ec.add(ec.mul(b, ec.G), ec.mul(rs[i], ec.H))
        cs.append(ec.encode(Ci).hex())
        proofs.append(_or_prove_full(b, rs[i], Ci, context, i))
    return {"bits": bits, "bit_commitments": cs, "bit_proofs": proofs}


def _or_prove_full(bit, r, C, ctx, idx):
    """CDS OR-proof that C commits to 0 or 1, with the two announcements published so the verifier recomputes the challenge."""
    T = (C, ec.add(C, ec.neg(ec.G)))
    sim = 1 - bit
    k, c_sim, s_sim = _scalar(), _scalar(), _scalar()
    R = [None, None]
    R[bit] = ec.mul(k, ec.H)
    R[sim] = ec.add(ec.mul(s_sim, ec.H), ec.neg(ec.mul(c_sim, T[sim])))
    c_total = ec.hash_to_scalar(b"VEGA-BIT-2", ctx, idx, ec.encode(C), ec.encode(R[0]), ec.encode(R[1]))
    c_real = (c_total - c_sim) % ec.N
    s_real = (k + c_real * r) % ec.N
    c0, s0, s1 = (c_real, s_real, s_sim) if bit == 0 else (c_sim, s_sim, s_real)
    return {"R0": ec.encode(R[0]).hex(), "R1": ec.encode(R[1]).hex(), "c0": _hx(c0), "s0": _hx(s0), "s1": _hx(s1)}


def _or_verify_full(C, ctx, idx, pr) -> bool:
    R0, R1 = _pt(pr["R0"]), _pt(pr["R1"])
    c0, s0, s1 = _sc(pr["c0"]), _sc(pr["s0"]), _sc(pr["s1"])
    c_total = ec.hash_to_scalar(b"VEGA-BIT-2", ctx, idx, ec.encode(C), ec.encode(R0), ec.encode(R1))
    c1 = (c_total - c0) % ec.N
    T0, T1 = C, ec.add(C, ec.neg(ec.G))
    return (ec.mul(s0, ec.H) == ec.add(R0, ec.mul(c0, T0))) and (ec.mul(s1, ec.H) == ec.add(R1, ec.mul(c1, T1)))


def verify_range(commitment: bytes, bits: int, proof, context: bytes = b"") -> bool:
    try:
        if not isinstance(bits, int) or isinstance(bits, bool) or not 1 <= bits <= MAX_BITS:
            return False
        if proof["bits"] != bits or len(proof["bit_commitments"]) != bits or len(proof["bit_proofs"]) != bits:
            return False
        C = _pt(commitment)
        total = ec.INF
        for i in range(bits):
            Ci = _pt(proof["bit_commitments"][i])
            if not _or_verify_full(Ci, context, i, proof["bit_proofs"][i]):
                return False
            total = ec.add(total, ec.mul(1 << i, Ci))
        return total == C
    except (ZKRefused, KeyError, TypeError, ValueError, IndexError):
        return False


# ---- at-least proof ---------------------------------------------------------------------------------------------
def prove_at_least(value: int, blinding: int, threshold: int, bits: int, context: bytes = b"") -> dict:
    if isinstance(threshold, bool) or not isinstance(threshold, int) or threshold < 0:
        raise ZKRefused("threshold is a non-negative whole number")
    if value < threshold:
        raise ZKRefused("the value is below the threshold: no honest proof exists")
    return {"threshold": threshold, "range": prove_range(value - threshold, blinding, bits, b"AT-LEAST|" + str(threshold).encode() + b"|" + context)}


def verify_at_least(commitment: bytes, threshold: int, bits: int, proof, context: bytes = b"") -> bool:
    try:
        if proof["threshold"] != threshold or isinstance(threshold, bool) or not isinstance(threshold, int) or threshold < 0:
            return False
        shifted = ec.encode(ec.add(_pt(commitment), ec.neg(ec.mul(threshold, ec.G))))
        return verify_range(shifted, bits, proof["range"], b"AT-LEAST|" + str(threshold).encode() + b"|" + context)
    except (ZKRefused, KeyError, TypeError):
        return False


# ---- who vouches for the hidden number --------------------------------------------------------------------------
def _att_msg(commitment: bytes, label: str) -> bytes:
    return b"VEGA-ATTEST-1|" + label.encode("utf-8") + b"|" + bytes(commitment)


def attest(issuer_private, commitment: bytes, label: str) -> str:
    """The issuer (employer, bank, school) signs the commitment and a label such as 'monthly_income_cents'. Returns hex."""
    if not isinstance(label, str) or not label or "|" in label:
        raise ZKRefused("label is plain text without '|'")
    return issuer_private.sign(_att_msg(commitment, label)).hex()


def verify_attestation(issuer_public: bytes, commitment: bytes, label: str, sig_hex: str) -> bool:
    try:
        Ed25519PublicKey.from_public_bytes(issuer_public).verify(bytes.fromhex(sig_hex), _att_msg(commitment, label))
        return True
    except (InvalidSignature, ValueError, TypeError):
        return False
