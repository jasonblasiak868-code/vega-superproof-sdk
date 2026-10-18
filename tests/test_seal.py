"""Selftest: exit 0 only if every check passes."""
import base64
import os
import pathlib
import secrets
import sys
import tempfile
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
from cryptography.exceptions import InvalidTag  # noqa: E402
from vega_custody.capsule import capsule as cap  # noqa: E402
from vega_custody.dag.dag import Dag  # noqa: E402
from vega_custody.ledger.backend_local import LocalBackend  # noqa: E402
from vega_custody.ledger.ledger import Ledger  # noqa: E402
from vega_superproof.seal import fhe, keysplit, layers, presets, proof_tier1, scrambler, signature, superproof  # noqa: E402
from vega_superproof.seal.errors import SignatureUnavailable, TierUnavailable  # noqa: E402
from vega_superproof.seal.lineage import key_id  # noqa: E402

fails, N = [], 0


def check(name, cond):
    global N
    N += 1
    print(("PASS " if cond else "FAIL ") + name)
    if not cond:
        fails.append(name)


def raises(exc, fn):
    try:
        fn()
    except exc:
        return True
    return False


t = pathlib.Path(tempfile.mkdtemp())
dag = Dag([t / "c.jsonl"], [t / "l.jsonl"])
led = Ledger([LocalBackend(t / "led.jsonl")])
sk, pub = signature.new_ed25519()
k1, k2 = secrets.token_bytes(32), secrets.token_bytes(32)
PLAIN_SENTINEL = "the-plaintext-that-must-never-reach-a-record"
c = cap.make(PLAIN_SENTINEL, {"source": "user"})

# --- layers
env = layers.seal_layers(b"hello", k1, k2, b"aad")
check("two layers open with both keys", layers.open_layers(env, k1, k2, b"aad") == b"hello")
check("wrong key 2 rejected", raises(InvalidTag, lambda: layers.open_layers(env, k1, secrets.token_bytes(32), b"aad")))
check("wrong key 1 rejected", raises(InvalidTag, lambda: layers.open_layers(env, secrets.token_bytes(32), k2, b"aad")))
bad = dict(env)
raw = bytearray(base64.b64decode(env["ct_b64"]))
raw[0] ^= 1
bad["ct_b64"] = base64.b64encode(bytes(raw)).decode()
check("tampered ciphertext rejected", raises(Exception, lambda: layers.open_layers(bad, k1, k2, b"aad")))
check("identical keys refused", raises(ValueError, lambda: layers.seal_layers(b"x", k1, k1)))
check("algorithm tags present", env["alg1"] == "aes-256-gcm" and env["alg2"] == "chacha20-poly1305")

# --- full pipeline, tier 0
sealed = superproof.seal(c, k1, k2, sk, pub, dag, led, "standard")
check("seal verifies independently", superproof.verify_seal(sealed, pub, led))
check("seal opens back to the capsule", superproof.open_seal(sealed, k1, k2) == c)
stages = [e["kind"] for e in dag.content.entries() if e["kind"].startswith("STAGE:")]
check("every stage DAGed in order", stages == ["STAGE:capsule", "STAGE:layer1-aes-256-gcm",
                                              "STAGE:layer2-chacha20-poly1305", "STAGE:lineage-root",
                                              "STAGE:proof-tier0"])
audit = [e for e in dag.content.entries() if e["kind"] == "SEAL_AUDIT"][-1]["payload"]
check("audit records tier and preset hash", audit["tier"] == 0 and audit["preset_hash"] == sealed["preset_hash"])
blob = b"".join(p.read_bytes() for p in (t / "c.jsonl", t / "l.jsonl", t / "led.jsonl") if p.exists())
check("plaintext never reaches DAG or ledger", PLAIN_SENTINEL.encode() not in blob)
check("keys never reach DAG or ledger", k1.hex().encode() not in blob and k2.hex().encode() not in blob)
tampered = dict(sealed)
tampered["top_root"] = "0" * 64
check("altered top root fails verification", not superproof.verify_seal(tampered, pub, led))
_, other_pub = signature.new_ed25519()
check("wrong public key fails verification", not superproof.verify_seal(sealed, other_pub, led))

# --- tiers fail closed, never downgrade
before = (len(dag.content), len(led.chain))
check("tier 1 without prover refuses", raises(TierUnavailable, lambda: superproof.seal(c, k1, k2, sk, pub, dag, led, "high_assurance")))
check("tier 2 without prover refuses", raises(TierUnavailable, lambda: superproof.seal(c, k1, k2, sk, pub, dag, led, "maximum")))
check("refused seal wrote nothing", (len(dag.content), len(led.chain)) == before)
check("pq signature without signer refuses", raises(SignatureUnavailable, lambda: superproof.seal(c, k1, k2, sk, pub, dag, led, "post_quantum")))


class FakeSnark:
    def prove(self, statement):
        return b"proof:" + str(sorted(statement)).encode()

    def verify(self, statement, proof):
        return proof.startswith(b"proof:")


proof_tier1.register(FakeSnark())
s1 = superproof.seal(c, k1, k2, sk, pub, dag, led, "high_assurance")
check("tier 1 works once a prover is registered", s1["proof"]["tier"] == 1 and superproof.verify_seal(s1, pub, led))

# --- scrambler (key re-wrap)
dek = secrets.token_bytes(32)
kek_old, kek_new = secrets.token_bytes(32), secrets.token_bytes(32)
w = scrambler.wrap(dek, kek_old)
unminted = {"kind": "WCOMMIT", "action": "rotate_keys", "expiry": int(time.time()) + 300,
            "action_hash": "a" * 64, "nonce_sha256": "b" * 64}
check("rotation with unminted commitment refused",
      raises(scrambler.RotationRefused, lambda: scrambler.rotate(w, kek_old, kek_new, led, dag, unminted)))
com = {"kind": "WCOMMIT", "device": "d", "surface": "s", "action": "rotate_keys", "action_hash": "c" * 64,
       "expiry": int(time.time()) + 300, "nonce_sha256": "d" * 64}
led.mint(com)
res = scrambler.rotate(w, kek_old, kek_new, led, dag, com)
check("rotation with fresh commitment re-wraps same data key", scrambler.unwrap(res["wrapped"], kek_new) == dek)
check("old key no longer opens the new wrap", raises(InvalidTag, lambda: scrambler.unwrap(res["wrapped"], kek_old)))
check("rotation recorded, old key retired",
      any(e["kind"] == "ROTATION" and e["payload"]["retired"] == [key_id(kek_old)] for e in dag.content.entries()))
check("same commitment cannot rotate twice",
      raises(scrambler.RotationRefused, lambda: scrambler.rotate(res["wrapped"], kek_new, kek_old, led, dag, com)))
com_wrong = {**com, "action": "write_file", "nonce_sha256": "e" * 64}
led.mint(com_wrong)
check("commitment for another action refused",
      raises(scrambler.RotationRefused, lambda: scrambler.rotate(res["wrapped"], kek_new, kek_old, led, dag, com_wrong)))

# --- fhe
check("locked compute without backend refuses (no plaintext fallback)",
      raises(fhe.FHEUnavailable, lambda: fhe.locked_compute("sum", [b"a", b"b"])))

# --- keysplit
secret = secrets.token_bytes(32)
sh = keysplit.split_roles(secret, 2)
pairs = [("tpm", "card"), ("tpm", "human"), ("card", "human")]
check("any 2 of 3 roles rebuild the secret", all(keysplit.combine([sh[a], sh[b]]) == secret for a, b in pairs))
check("1 share alone is refused (and reveals nothing)", raises(ValueError, lambda: keysplit.combine([sh["tpm"]])))
check("3-of-5 split works", keysplit.combine(keysplit.split(secret, 3, 5)[1:4]) == secret)

# --- presets
check("preset hash stable and distinct",
      presets.preset_hash(presets.preset_card("standard")) == presets.preset_hash(presets.preset_card("standard"))
      and presets.preset_hash(presets.preset_card("standard")) != presets.preset_hash(presets.preset_card("maximum")))

print(f"{N - len(fails)}/{N} passed" if not fails else f"FAILED: {fails}")
sys.exit(1 if fails else 0)
