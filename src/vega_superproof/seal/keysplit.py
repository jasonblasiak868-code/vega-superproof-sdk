"""keysplit.py - split a secret across roles (TPM, card, human) so no single holder can use it. Shamir secret
sharing over GF(256): any k of n shares rebuild the secret, fewer than k reveal nothing about it.
Stdlib only. Each share is (x, bytes); keep x with the share."""
import secrets

# GF(256) with the AES polynomial 0x11b, generator 3
_EXP, _LOG = [0] * 512, [0] * 256
_x = 1
for _i in range(255):
    _EXP[_i] = _x
    _LOG[_x] = _i
    _x ^= (_x << 1) ^ (0x11B if _x & 0x80 else 0)
    _x &= 0xFF
for _i in range(255, 512):
    _EXP[_i] = _EXP[_i - 255]


def _mul(a, b):
    return 0 if a == 0 or b == 0 else _EXP[_LOG[a] + _LOG[b]]


def _div(a, b):
    if b == 0:
        raise ZeroDivisionError
    return 0 if a == 0 else _EXP[_LOG[a] + 255 - _LOG[b]]


def split(secret: bytes, k: int, n: int):
    if not (2 <= k <= n <= 255):
        raise ValueError("need 2 <= k <= n <= 255")
    shares = [(x, bytearray()) for x in range(1, n + 1)]
    for byte in secret:
        coeffs = [byte] + [secrets.randbelow(256) for _ in range(k - 1)]
        for x, buf in shares:
            y = 0
            for c in reversed(coeffs):
                y = _mul(y, x) ^ c
            buf.append(y)
    return [(x, bytes(b)) for x, b in shares]


def _check_shares(shares):
    if not isinstance(shares, (list, tuple)) or len(shares) < 2:
        raise ValueError("combine needs at least 2 shares (the threshold is never below 2)")
    for sh in shares:
        if not (isinstance(sh, (list, tuple)) and len(sh) == 2 and isinstance(sh[0], int) and not isinstance(sh[0], bool) and 1 <= sh[0] <= 255
                and isinstance(sh[1], (bytes, bytearray))):
            raise ValueError("a share is (x, bytes) with x in 1..255")


def combine(shares) -> bytes:
    """Rebuilds a secret from shares. WARNING: plain Shamir cannot tell whether it has enough shares or whether one is corrupt: it returns SOME bytes either way.
    Use split_checked()/combine_checked() so a wrong answer is detected."""
    _check_shares(shares)
    xs = [x for x, _ in shares]
    if len(set(xs)) != len(xs):
        raise ValueError("duplicate shares")
    length = len(shares[0][1])
    if any(len(b) != length for _, b in shares):
        raise ValueError("share lengths differ")
    out = bytearray()
    for i in range(length):
        acc = 0
        for xi, bi in shares:
            num, den = 1, 1
            for xj, _ in shares:
                if xj != xi:
                    num = _mul(num, xj)
                    den = _mul(den, xi ^ xj)
            acc ^= _mul(bi[i], _div(num, den))
        out.append(acc)
    return bytes(out)


def _check_tag(secret: bytes, k: int, n: int) -> str:
    import hashlib
    return hashlib.sha256(b"vega-keysplit-check-v1|" + bytes([k, n]) + bytes(secret)).hexdigest()


def split_checked(secret: bytes, k: int, n: int):
    """Returns (shares, check). The check is a hash of the secret: safe for a random key, NOT for a guessable secret (it would allow offline guessing)."""
    return split(secret, k, n), _check_tag(secret, k, n)


def combine_checked(shares, check: str, k: int, n: int) -> bytes:
    """Rebuild and verify. Raises ValueError if the shares were too few, wrong, or corrupt."""
    secret = combine(shares)
    if _check_tag(secret, k, n) != check:
        raise ValueError("the rebuilt secret does not match its check: too few shares, a wrong share, or a corrupt share")
    return secret


ROLES = ("tpm", "card", "human")


def split_roles(secret: bytes, k: int = 2):
    """One share per role. Default 2-of-3: any two of TPM, card, human rebuild; one alone cannot."""
    return dict(zip(ROLES, split(secret, k, len(ROLES))))
