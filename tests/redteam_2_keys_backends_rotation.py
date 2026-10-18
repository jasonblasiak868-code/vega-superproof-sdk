"""RED TEAM PASS 2 (superproof): key splitting, backend registration, fail-closed tiers, and rotation."""
import pathlib
import random
import secrets
import tempfile
import time
import unittest

from cryptography.exceptions import InvalidTag

from vega_custody.capsule import capsule as cap
from vega_custody.dag.dag import Dag
from vega_custody.ledger.backend_local import LocalBackend
from vega_custody.ledger.ledger import Ledger
from vega_superproof.seal import fhe, keysplit, layers, lineage, proof_tier1, proof_tier2, scrambler, signature, superproof
from vega_superproof.seal.errors import SignatureUnavailable, TierUnavailable


class KeySplitAttacks(unittest.TestCase):
    def test_too_few_wrong_or_malformed_shares_are_never_silently_accepted(self):
        secret = secrets.token_bytes(32)
        sh = keysplit.split(secret, 3, 5)
        with self.assertRaises(ValueError):
            keysplit.combine(sh[:1])
        with self.assertRaises(ValueError):
            keysplit.combine([sh[0], sh[0]])
        for bad in ([(0, b"x"), (1, b"y")], [(256, b"x"), (1, b"y")], [(True, b"x"), (2, b"y")], [(1, "text"), (2, b"y")], [(1,), (2, b"y")], None, "ab", []):
            with self.assertRaises(ValueError, msg=repr(bad)):
                keysplit.combine(bad)

    def test_checked_combine_detects_too_few_a_wrong_share_and_a_corrupt_share(self):
        secret = secrets.token_bytes(32)
        shares, check = keysplit.split_checked(secret, 3, 5)
        self.assertEqual(keysplit.combine_checked(shares[:3], check, 3, 5), secret)
        self.assertEqual(keysplit.combine_checked([shares[4], shares[0], shares[2]], check, 3, 5), secret)
        with self.assertRaises(ValueError):                                   # two shares of a 3-of-5 split rebuild SOMETHING, but not the secret
            keysplit.combine_checked(shares[:2], check, 3, 5)
        x, b = shares[1]
        corrupt = [shares[0], (x, bytes([b[0] ^ 1]) + b[1:]), shares[2]]
        with self.assertRaises(ValueError):
            keysplit.combine_checked(corrupt, check, 3, 5)

    def test_random_secrets_and_random_subsets_always_rebuild(self):
        rnd = random.Random(7)
        for _ in range(60):
            k = rnd.randint(2, 6)
            n = rnd.randint(k, 9)
            secret = secrets.token_bytes(rnd.choice([1, 16, 32, 33]))
            shares = keysplit.split(secret, k, n)
            pick = rnd.sample(shares, rnd.randint(k, n))
            self.assertEqual(keysplit.combine(pick), secret)

    def test_below_threshold_subsets_do_not_equal_the_secret(self):
        for _ in range(40):
            secret = secrets.token_bytes(16)
            shares = keysplit.split(secret, 3, 5)
            self.assertNotEqual(keysplit.combine(random.sample(shares, 2)), secret)


class RegistryAttacks(unittest.TestCase):
    def tearDown(self):
        signature._BACKENDS.clear()
        proof_tier1._BACKEND = None
        proof_tier2._BACKEND = None
        fhe._BACKEND = None

    def test_a_backend_cannot_be_silently_replaced(self):
        """Attack: any importing code swaps in a verifier that always says yes."""
        class B:
            def sign(self, p, m): return b""
            def verify(self, p, m, s): return True
            def prove(self, st): return b""
            def evaluate(self, o, c): return None
        a, b = B(), B()
        signature.register("ml-dsa-65", a)
        signature.register("ml-dsa-65", a)                                      # same object: idempotent
        with self.assertRaises(ValueError):
            signature.register("ml-dsa-65", b)
        signature.register("ml-dsa-65", b, replace=True)                        # a deliberate change is allowed
        with self.assertRaises(ValueError):
            signature.register("ed25519", a)
        proof_tier1.register(a)
        with self.assertRaises(ValueError):
            proof_tier1.register(b)
        proof_tier2.register(a)
        with self.assertRaises(ValueError):
            proof_tier2.register(b)
        fhe.register_backend(a)
        with self.assertRaises(ValueError):
            fhe.register_backend(b)

    def test_unavailable_tiers_and_signers_refuse_before_anything_is_written(self):
        t = pathlib.Path(tempfile.mkdtemp())
        dag = Dag([t / "c.jsonl"], [t / "l.jsonl"])
        led = Ledger([LocalBackend(t / "led.jsonl")])
        sk, pub = signature.new_ed25519()
        k1, k2 = layers.generate_key(), layers.generate_key()
        c = cap.make("x", {"source": "u"})
        n = len(dag.content.entries())
        with self.assertRaises(TierUnavailable):
            superproof.seal(c, k1, k2, sk, pub, dag, led, preset="high_assurance")
        with self.assertRaises(TierUnavailable):
            superproof.seal(c, k1, k2, sk, pub, dag, led, preset="maximum")
        with self.assertRaises(SignatureUnavailable):
            superproof.seal(c, k1, k2, sk, pub, dag, led, preset="post_quantum")
        with self.assertRaises(KeyError):
            superproof.seal(c, k1, k2, sk, pub, dag, led, preset="nope")
        self.assertEqual(len(dag.content.entries()), n, "a refused seal must leave no trace")
        with self.assertRaises(fhe.FHEUnavailable):
            fhe.locked_compute("add", [b"x"])


class RotationAttacks(unittest.TestCase):
    def setUp(self):
        t = pathlib.Path(tempfile.mkdtemp())
        self.dag = Dag([t / "c.jsonl"], [t / "l.jsonl"])
        self.led = Ledger([LocalBackend(t / "led.jsonl")])
        self.dek, self.kek1, self.kek2 = layers.generate_key(), layers.generate_key(), layers.generate_key()
        self.wrapped = scrambler.wrap(self.dek, self.kek1)
        self.n = 0

    def commitment(self, action="rotate_keys", expiry=None, mint=True):
        self.n += 1
        c = {"kind": "WCOMMIT", "device": "d", "surface": "s", "action": action, "action_hash": f"{self.n:064x}", "expiry": expiry or int(time.time()) + 300, "nonce_sha256": f"{self.n + 50:064x}"}
        if mint:
            self.led.mint(c)
        return c

    def test_rotation_needs_a_fresh_minted_single_use_commitment_for_exactly_this_action(self):
        for kw in ({"action": "other"}, {"expiry": 1}, {"mint": False}):
            with self.assertRaises(scrambler.RotationRefused):
                scrambler.rotate(self.wrapped, self.kek1, self.kek2, self.led, self.dag, self.commitment(**kw))
        c = self.commitment()
        out = scrambler.rotate(self.wrapped, self.kek1, self.kek2, self.led, self.dag, c)
        self.assertEqual(scrambler.unwrap(out["wrapped"], self.kek2), self.dek)
        with self.assertRaises(scrambler.RotationRefused):                       # same commitment again
            scrambler.rotate(out["wrapped"], self.kek2, self.kek1, self.led, self.dag, c)

    def test_a_retired_key_cannot_be_used_to_rotate_again(self):
        out = scrambler.rotate(self.wrapped, self.kek1, self.kek2, self.led, self.dag, self.commitment())
        with self.assertRaises(scrambler.RotationRefused):
            scrambler.rotate(self.wrapped, self.kek1, layers.generate_key(), self.led, self.dag, self.commitment())
        self.assertTrue(self.dag.verify()[0])

    def test_wrapped_keys_reject_tampering_and_wrong_keys(self):
        raw = bytearray(self.wrapped)
        raw[20] ^= 1
        with self.assertRaises(InvalidTag):
            scrambler.unwrap(bytes(raw), self.kek1)
        with self.assertRaises(InvalidTag):
            scrambler.unwrap(self.wrapped, self.kek2)
        with self.assertRaises(InvalidTag):
            scrambler.unwrap(self.wrapped, self.kek1, aad=b"other-context")

    def test_key_ids_are_not_the_plain_hash_of_the_key_and_differ_per_key(self):
        import hashlib
        self.assertNotEqual(lineage.key_id(self.kek1), hashlib.sha256(self.kek1).hexdigest())
        self.assertNotEqual(lineage.key_id(self.kek1), lineage.key_id(self.kek2))
        self.assertEqual(lineage.key_id(self.kek1), lineage.key_id(self.kek1))


if __name__ == "__main__":
    unittest.main()
