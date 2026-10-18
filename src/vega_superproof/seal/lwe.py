"""lwe.py - computation on locked data, with encryption that can be UPDATED: a learning-with-errors (LWE) scheme, additively homomorphic, with key rotation.

What it can do: a holder encrypts whole numbers; ANYONE holding only the ciphertexts can add them, subtract them and multiply them by plain numbers (so they can
compute sums, averages and linear scores such as a weighted total) without ever seeing the numbers or the key. Only the key holder can decrypt the result.
UPDATING ENCRYPTION: the holder rotates to a new secret key; the rotation produces a SWITCH KEY that lets the evaluator move every ciphertext from the old key to
the new one WITHOUT decrypting. Ciphertexts and keys carry an EPOCH number; mixing epochs is refused. After rotation the old secret is wiped, so a later theft
of the old key opens nothing that was switched (provided every old copy of the ciphertexts is also deleted).

WHAT IT CANNOT DO (read this): it is additive only. There is no ciphertext-times-ciphertext multiplication, so it is NOT fully homomorphic: no encrypted
comparisons, no neural-network activations. Those need a full FHE library (registered through fhe.register_backend); this one is for linear work.
NOISE: every ciphertext carries a worst-case noise bound; an operation that would let the noise reach the decryption limit is refused, never silently wrong.
SECURITY: the default parameters (n=512, q=2^48) are in the range people use for lattice schemes, but these exact choices, this code and its key-switching have had
NO independent cryptographic review, are not constant-time, and use Python's secrets module. Treat it as a working research model: do not protect real secrets with
it before a review. Small test parameters (n < 256) are deliberately insecure."""
import hashlib
import json
import secrets

ETA = 21                          # centered binomial noise: |e| <= 21, standard deviation about 3.2


class LweError(Exception):
    pass


class NoiseBudgetExhausted(LweError):
    pass


class Params:
    def __init__(self, n: int = 512, q_bits: int = 48, t_bits: int = 16, base_bits: int = 8):
        for v in (n, q_bits, t_bits, base_bits):
            if isinstance(v, bool) or not isinstance(v, int) or v < 1:
                raise LweError("parameters are positive whole numbers")
        if not 8 <= n <= 4096 or not 16 <= q_bits <= 62 or not 1 <= t_bits < q_bits - 8 or base_bits > 16:
            raise LweError("parameter out of range")
        self.n, self.q, self.t, self.delta = n, 1 << q_bits, 1 << t_bits, 1 << (q_bits - t_bits)
        self.base_bits, self.digits = base_bits, -(-q_bits // base_bits)
        self.insecure = n < 256
        self.id = hashlib.sha256(json.dumps([n, q_bits, t_bits, base_bits]).encode()).hexdigest()[:16]

    @property
    def limit(self):
        """Decryption is correct while the noise is below delta / 2."""
        return self.delta // 2


def _noise() -> int:
    return bin(secrets.randbits(ETA)).count("1") - bin(secrets.randbits(ETA)).count("1")


def _rand_vec(n, q):
    bits = q.bit_length() - 1
    return [secrets.randbits(bits) for _ in range(n)]


class Ciphertext:
    __slots__ = ("params_id", "epoch", "a", "b", "noise")

    def __init__(self, params_id, epoch, a, b, noise):
        self.params_id, self.epoch, self.a, self.b, self.noise = params_id, epoch, a, b, noise

    def to_dict(self):
        return {"params": self.params_id, "epoch": self.epoch, "a": self.a, "b": self.b, "noise": self.noise}

    @classmethod
    def from_dict(cls, d, params: Params):
        try:
            if d["params"] != params.id or not isinstance(d["epoch"], int) or isinstance(d["epoch"], bool) or d["epoch"] < 0:
                raise LweError("not a ciphertext of these parameters")
            a, b, nz = d["a"], d["b"], d["noise"]
            if not isinstance(a, list) or len(a) != params.n or not all(isinstance(x, int) and not isinstance(x, bool) and 0 <= x < params.q for x in a):
                raise LweError("bad ciphertext vector")
            if not isinstance(b, int) or isinstance(b, bool) or not 0 <= b < params.q or not isinstance(nz, int) or isinstance(nz, bool) or nz < 0:
                raise LweError("bad ciphertext body")
            return cls(d["params"], d["epoch"], list(a), b, nz)
        except (KeyError, TypeError) as exc:
            raise LweError("malformed ciphertext") from exc


class SwitchKey:
    """Public material that moves ciphertexts from `from_epoch` to `to_epoch`. It reveals nothing about either secret."""
    __slots__ = ("params_id", "from_epoch", "to_epoch", "rows")

    def __init__(self, params_id, from_epoch, to_epoch, rows):
        self.params_id, self.from_epoch, self.to_epoch, self.rows = params_id, from_epoch, to_epoch, rows


class KeyHolder:
    """The only object that can encrypt or decrypt. Its secret never leaves it."""

    def __init__(self, params: Params = None, epoch: int = 0):
        self.params = params or Params()
        self.epoch = epoch
        self._s = [secrets.randbelow(3) - 1 for _ in range(self.params.n)]
        self._alive = True

    def _check(self):
        if not self._alive:
            raise LweError("this key has been wiped (it was rotated away)")

    def encrypt(self, m: int) -> Ciphertext:
        self._check()
        p = self.params
        if isinstance(m, bool) or not isinstance(m, int) or not 0 <= m < p.t:
            raise LweError("plaintext is a whole number from 0 to %d" % (p.t - 1))
        a = _rand_vec(p.n, p.q)
        b = (sum(x * y for x, y in zip(a, self._s)) + _noise() + p.delta * m) % p.q
        return Ciphertext(p.id, self.epoch, a, b, ETA)

    def decrypt(self, ct: Ciphertext) -> int:
        self._check()
        p = self.params
        if ct.params_id != p.id or ct.epoch != self.epoch:
            raise LweError("this ciphertext is from another epoch or parameter set (switch it first)")
        if ct.noise >= p.limit:
            raise NoiseBudgetExhausted("the noise bound has reached the decryption limit: the result would be wrong")
        phase = (ct.b - sum(x * y for x, y in zip(ct.a, self._s))) % p.q
        return ((phase + p.delta // 2) // p.delta) % p.t

    def rotate(self):
        """-> (new KeyHolder at epoch+1, SwitchKey old->new). The OLD secret is wiped here."""
        self._check()
        p = self.params
        new = KeyHolder(p, self.epoch + 1)
        base = 1 << p.base_bits
        rows = []
        for i in range(p.n):
            row = []
            for j in range(p.digits):
                alpha = _rand_vec(p.n, p.q)
                beta = (sum(x * y for x, y in zip(alpha, new._s)) + _noise() + self._s[i] * pow(base, j)) % p.q
                row.append((alpha, beta))
            rows.append(row)
        sk = SwitchKey(p.id, self.epoch, new.epoch, rows)
        self.destroy()
        return new, sk

    def destroy(self):
        self._s = [0] * len(self._s)
        self._alive = False


# ---- the evaluator side: no secret needed ---------------------------------------------------------------------------
def _same(p: Params, *cts):
    first = cts[0]
    for c in cts:
        if c.params_id != p.id or c.epoch != first.epoch:
            raise LweError("ciphertexts must share parameters and epoch")


def _guard(p, noise):
    if noise >= p.limit:
        raise NoiseBudgetExhausted("this operation would exhaust the noise budget; decrypt, re-encrypt or use fewer / smaller operations")
    return noise


def add(p: Params, x: Ciphertext, y: Ciphertext) -> Ciphertext:
    _same(p, x, y)
    return Ciphertext(p.id, x.epoch, [(u + v) % p.q for u, v in zip(x.a, y.a)], (x.b + y.b) % p.q, _guard(p, x.noise + y.noise))


def sub(p: Params, x: Ciphertext, y: Ciphertext) -> Ciphertext:
    _same(p, x, y)
    return Ciphertext(p.id, x.epoch, [(u - v) % p.q for u, v in zip(x.a, y.a)], (x.b - y.b) % p.q, _guard(p, x.noise + y.noise))


def scale(p: Params, x: Ciphertext, k: int) -> Ciphertext:
    """Multiply by a plain whole number (0 <= k < t); the result decrypts to k*m mod t."""
    _same(p, x)
    if isinstance(k, bool) or not isinstance(k, int) or not 0 <= k < p.t:
        raise LweError("the multiplier is a whole number from 0 to %d" % (p.t - 1))
    return Ciphertext(p.id, x.epoch, [(u * k) % p.q for u in x.a], (x.b * k) % p.q, _guard(p, x.noise * k))


def total(p: Params, cts) -> Ciphertext:
    cts = list(cts)
    if not cts:
        raise LweError("nothing to add")
    acc = cts[0]
    for c in cts[1:]:
        acc = add(p, acc, c)
    return acc


def dot(p: Params, cts, weights) -> Ciphertext:
    """The linear score: sum of weight_i * ciphertext_i, computed on locked data."""
    cts, weights = list(cts), list(weights)
    if len(cts) != len(weights) or not cts:
        raise LweError("one weight per ciphertext")
    return total(p, [scale(p, c, w) for c, w in zip(cts, weights)])


def switch(p: Params, ct: Ciphertext, sk: SwitchKey) -> Ciphertext:
    """Move a ciphertext to the new epoch without decrypting it."""
    if sk.params_id != p.id or ct.params_id != p.id or ct.epoch != sk.from_epoch:
        raise LweError("this switch key is not for this ciphertext's epoch")
    base_mask = (1 << p.base_bits) - 1
    a2 = [0] * p.n
    b2 = ct.b
    for i in range(p.n):
        ai = ct.a[i]
        for j in range(p.digits):
            d = (ai >> (j * p.base_bits)) & base_mask
            if d:
                alpha, beta = sk.rows[i][j]
                for k in range(p.n):
                    a2[k] -= d * alpha[k]
                b2 -= d * beta
    added = p.n * p.digits * base_mask * ETA
    return Ciphertext(p.id, sk.to_epoch, [x % p.q for x in a2], b2 % p.q, _guard(p, ct.noise + added))


class LweBackend:
    """Plugs into fhe.register_backend(): evaluate('add'|'sub'|'sum'|'scale:K'|'dot:K1,K2,...', [ciphertexts])."""

    def __init__(self, params: Params):
        self.p = params

    def evaluate(self, operation: str, ciphertexts: list):
        p = self.p
        if operation == "add" and len(ciphertexts) == 2:
            return add(p, *ciphertexts)
        if operation == "sub" and len(ciphertexts) == 2:
            return sub(p, *ciphertexts)
        if operation == "sum":
            return total(p, ciphertexts)
        if operation.startswith("scale:") and len(ciphertexts) == 1:
            return scale(p, ciphertexts[0], int(operation[6:]))
        if operation.startswith("dot:"):
            return dot(p, ciphertexts, [int(w) for w in operation[4:].split(",")])
        raise LweError("unknown or malformed operation (this backend is additive only)")
