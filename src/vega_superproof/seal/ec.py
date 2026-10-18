"""ec.py - secp256k1 group arithmetic in plain Python, for the zero-knowledge tier (Schnorr, Pedersen, range proofs).

Written for correctness and checkability, not speed (a few milliseconds per point multiplication) and NOT constant-time: do not use it where a local
attacker can time the machine. The curve constants are checked when the module loads (G is on the curve and n*G is the point at infinity); a typo fails
the import rather than quietly weakening anything.
Classical security only: these groups fall to a large quantum computer. The quantum-proof tier uses hashes instead (hashsig.py, disclosure.py)."""
import hashlib

P = 2**256 - 2**32 - 977
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
GX = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
GY = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8
INF = None


class ECError(ValueError):
    pass


def on_curve(pt) -> bool:
    if pt is INF:
        return True
    x, y = pt
    return 0 <= x < P and 0 <= y < P and (y * y - (x * x * x + 7)) % P == 0


def add(a, b):
    if a is INF:
        return b
    if b is INF:
        return a
    x1, y1 = a
    x2, y2 = b
    if x1 == x2:
        if (y1 + y2) % P == 0:
            return INF
        lam = (3 * x1 * x1) * pow(2 * y1, -1, P) % P
    else:
        lam = (y2 - y1) * pow(x2 - x1, -1, P) % P
    x3 = (lam * lam - x1 - x2) % P
    return (x3, (lam * (x1 - x3) - y1) % P)


def neg(a):
    return INF if a is INF else (a[0], (-a[1]) % P)


def mul(k: int, pt):
    k %= N
    if k == 0 or pt is INF:
        return INF
    acc, add_pt = INF, pt
    while k:
        if k & 1:
            acc = add(acc, add_pt)
        add_pt = add(add_pt, add_pt)
        k >>= 1
    return acc


G = (GX, GY)
if not on_curve(G) or mul(N, G) is not INF or mul(N - 1, G) != neg(G):
    raise ECError("curve constants failed their self-check")


def encode(pt) -> bytes:
    """33-byte compressed point; 33 zero bytes for infinity."""
    if pt is INF:
        return b"\x00" * 33
    return bytes([2 + (pt[1] & 1)]) + pt[0].to_bytes(32, "big")


def decode(b: bytes):
    if not isinstance(b, (bytes, bytearray)) or len(b) != 33:
        raise ECError("a point is 33 bytes")
    if bytes(b) == b"\x00" * 33:
        return INF
    if b[0] not in (2, 3):
        raise ECError("bad point prefix")
    x = int.from_bytes(b[1:], "big")
    if x >= P:
        raise ECError("x out of range")
    y = pow((x * x * x + 7) % P, (P + 1) // 4, P)
    if y * y % P != (x * x * x + 7) % P:
        raise ECError("not on the curve")
    if (y & 1) != (b[0] & 1):
        y = P - y
    return (x, y)


def hash_to_scalar(*parts) -> int:
    h = hashlib.sha256()
    for p in parts:
        b = p if isinstance(p, (bytes, bytearray)) else str(p).encode("utf-8")
        h.update(len(b).to_bytes(4, "big"))
        h.update(b)
    return int.from_bytes(h.digest(), "big") % N


def hash_to_point(seed: bytes):
    """A point nobody knows the discrete log of (try-and-increment from a public seed): the second Pedersen generator."""
    ctr = 0
    while True:
        x = int.from_bytes(hashlib.sha256(seed + ctr.to_bytes(4, "big")).digest(), "big") % P
        rhs = (x * x * x + 7) % P
        y = pow(rhs, (P + 1) // 4, P)
        if y * y % P == rhs:
            return (x, y if y % 2 == 0 else P - y)
        ctr += 1


H = hash_to_point(b"VEGA-SUPERPROOF-PEDERSEN-H-1")
