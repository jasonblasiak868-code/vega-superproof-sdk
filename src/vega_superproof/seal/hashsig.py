"""hashsig.py - the quantum-proof signature: a hash-based, stateful many-time signature (Winternitz one-time keys, w=16, under a Merkle tree), built on SHA-256 only.

Its security rests on the hash function and nothing else, so a large quantum computer does not break it the way it breaks Ed25519 (it halves a hash's security
at worst; SHA-256 keeps about 128 bits). This is the same family as XMSS (RFC 8391) and the stateful hash-based signatures NIST has approved, but it is NOT
interoperable with them and has had no independent review.

STATEFUL: each of the 2^height one-time keys must be used ONCE. The signer writes its next index to disk BEFORE it returns a signature, refuses to go backwards,
and refuses to sign when the keys run out. Restoring an old copy of the state file (a backup, a cloned machine) would reuse a key and let a forger sign: keep the
state file and the seed on one machine and never copy them. Signature size is about 2.2 kB plus 32 bytes per tree level.

  Signer(height, seed, state_path)   .public (64 bytes: public seed + tree root)   .sign(msg) -> bytes   .remaining
  verify(public, msg, sig) -> bool
  HashSigBackend / register()        plugs in as the signature algorithm 'hashsig-sha256-w16' for the seal"""
import hashlib
import hmac
import json
import os
import secrets
import threading

ALG = "hashsig-sha256-w16"
N = 32
W = 16
LEN1 = 64
LEN2 = 3
LEN = LEN1 + LEN2
MAX_HEIGHT = 10


class HashSigError(Exception):
    pass


def _h(*parts) -> bytes:
    h = hashlib.sha256()
    for p in parts:
        h.update(p)
    return h.digest()


def _chain(x: bytes, start: int, steps: int, pub_seed: bytes, leaf: int, i: int) -> bytes:
    for j in range(start, start + steps):
        x = _h(b"WOTS-F", pub_seed, leaf.to_bytes(4, "big"), i.to_bytes(2, "big"), j.to_bytes(1, "big"), x)
    return x


def _digits(digest: bytes):
    d = []
    for b in digest:
        d += [b >> 4, b & 15]
    csum = sum(W - 1 - x for x in d)
    return d + [(csum >> 8) & 15, (csum >> 4) & 15, csum & 15]


def _msg_digest(r: bytes, root: bytes, idx: int, msg: bytes) -> bytes:
    return _h(b"HASHSIG-MSG", r, root, idx.to_bytes(4, "big"), hashlib.sha256(msg).digest())


def _leaf_pk(ends, pub_seed, leaf) -> bytes:
    return _h(b"WOTS-LEAF", pub_seed, leaf.to_bytes(4, "big"), *ends)


def _node(left: bytes, right: bytes, pub_seed: bytes, level: int, pos: int) -> bytes:
    return _h(b"TREE-NODE", pub_seed, level.to_bytes(1, "big"), pos.to_bytes(4, "big"), left, right)


class Signer:
    def __init__(self, height: int = 6, seed: bytes = None, state_path=None, pub_seed: bytes = None):
        if not isinstance(height, int) or isinstance(height, bool) or not 1 <= height <= MAX_HEIGHT:
            raise HashSigError("height is 1 to %d" % MAX_HEIGHT)
        self.height = height
        self._seed = seed if seed is not None else secrets.token_bytes(32)
        if not isinstance(self._seed, (bytes, bytearray)) or len(self._seed) != 32:
            raise HashSigError("seed is 32 bytes")
        self._pub_seed = pub_seed if pub_seed is not None else _h(b"PUBSEED", bytes(self._seed))
        self._lock = threading.Lock()
        self._state = os.fspath(state_path) if state_path else None
        self._levels = self._build()
        self.root = self._levels[-1][0]
        self.public = self._pub_seed + self.root
        self._next = 0
        if self._state and os.path.exists(self._state):
            try:
                with open(self._state, "r", encoding="utf-8") as fh:
                    st = json.load(fh)
                if st.get("root") != self.root.hex() or not isinstance(st.get("next"), int) or st["next"] < 0:
                    raise ValueError
                self._next = st["next"]
            except (OSError, ValueError, TypeError) as exc:
                raise HashSigError("the state file is unreadable or belongs to another key: refusing to sign (a lost index could reuse a one-time key)") from exc
        elif self._state:
            self._save()

    def _sk(self, leaf, i):
        return hmac.new(bytes(self._seed), b"WOTS-SK" + leaf.to_bytes(4, "big") + i.to_bytes(2, "big"), hashlib.sha256).digest()

    def _ends(self, leaf):
        return [_chain(self._sk(leaf, i), 0, W - 1, self._pub_seed, leaf, i) for i in range(LEN)]

    def _build(self):
        level = [_leaf_pk(self._ends(l), self._pub_seed, l) for l in range(1 << self.height)]
        levels = [level]
        for lv in range(self.height):
            level = [_node(level[2 * k], level[2 * k + 1], self._pub_seed, lv + 1, k) for k in range(len(level) // 2)]
            levels.append(level)
        return levels

    def _save(self):
        tmp = self._state + ".tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump({"root": self.root.hex(), "next": self._next}, fh)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, self._state)

    @property
    def remaining(self) -> int:
        return (1 << self.height) - self._next

    def sign(self, msg: bytes) -> bytes:
        if not isinstance(msg, (bytes, bytearray)):
            raise HashSigError("msg is bytes")
        with self._lock:
            if self._next >= (1 << self.height):
                raise HashSigError("out of one-time keys: make a new key")
            idx = self._next
            self._next += 1
            if self._state:
                self._save()                                    # the index is on disk BEFORE the signature exists
            r = secrets.token_bytes(32)
            digits = _digits(_msg_digest(r, self.root, idx, bytes(msg)))
            sig = [_chain(self._sk(idx, i), 0, d, self._pub_seed, idx, i) for i, d in enumerate(digits)]
            auth, pos = [], idx
            for lv in range(self.height):
                auth.append(self._levels[lv][pos ^ 1])
                pos >>= 1
            return idx.to_bytes(4, "big") + r + b"".join(sig) + b"".join(auth)


def verify(public: bytes, msg: bytes, sig: bytes, height: int = None) -> bool:
    """height is read from the signature length when not given; a verifier that knows the key's height should pass it."""
    try:
        if not isinstance(public, (bytes, bytearray)) or len(public) != 64 or not isinstance(sig, (bytes, bytearray)) or not isinstance(msg, (bytes, bytearray)):
            return False
        base = 4 + 32 + LEN * N
        if len(sig) < base or (len(sig) - base) % N:
            return False
        h = (len(sig) - base) // N
        if h < 1 or h > MAX_HEIGHT or (height is not None and h != height):
            return False
        pub_seed, root = bytes(public[:32]), bytes(public[32:])
        idx = int.from_bytes(sig[:4], "big")
        if idx >= (1 << h):
            return False
        r = bytes(sig[4:36])
        digits = _digits(_msg_digest(r, root, idx, bytes(msg)))
        ends = [_chain(bytes(sig[36 + i * N:36 + (i + 1) * N]), d, W - 1 - d, pub_seed, idx, i) for i, d in enumerate(digits)]
        node, pos = _leaf_pk(ends, pub_seed, idx), idx
        for lv in range(h):
            sib = bytes(sig[base + lv * N:base + (lv + 1) * N])
            node = _node(node, sib, pub_seed, lv + 1, pos >> 1) if pos % 2 == 0 else _node(sib, node, pub_seed, lv + 1, pos >> 1)
            pos >>= 1
        return hmac.compare_digest(node, root)
    except (ValueError, TypeError, IndexError, OverflowError):
        return False


class HashSigBackend:
    """The shape signature.register() wants: sign(private, msg) and verify(public, msg, sig)."""

    def sign(self, private, msg: bytes) -> bytes:
        if not isinstance(private, Signer):
            raise HashSigError("the private key is a hashsig.Signer")
        return private.sign(msg)

    def verify(self, public: bytes, msg: bytes, sig: bytes) -> bool:
        return verify(public, msg, sig)


_BACKEND = HashSigBackend()


def register(replace: bool = False):
    from vega_superproof.seal import signature
    signature.register(ALG, _BACKEND, replace=replace)
