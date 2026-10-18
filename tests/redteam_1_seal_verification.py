"""RED TEAM PASS 1 (superproof): can a forged or altered seal still verify? Each attack below WORKED against the code before the 2026-10-16 fixes."""
import base64
import copy
import hashlib
import pathlib
import secrets
import tempfile
import unittest

from cryptography.exceptions import InvalidTag

from vega_custody.capsule import capsule as cap
from vega_custody.dag.dag import Dag
from vega_custody.ledger.backend_local import LocalBackend
from vega_custody.ledger.ledger import Ledger
from vega_superproof.seal import layers, signature, superproof


def fresh():
    t = pathlib.Path(tempfile.mkdtemp())
    dag = Dag([t / "c.jsonl"], [t / "l.jsonl"])
    led = Ledger([LocalBackend(t / "led.jsonl")])
    sk, pub = signature.new_ed25519()
    k1, k2 = layers.generate_key(), layers.generate_key()
    sealed = superproof.seal(cap.make("secret-payload", {"source": "user"}), k1, k2, sk, pub, dag, led)
    return dag, led, sk, pub, k1, k2, sealed


class T(unittest.TestCase):
    def setUp(self):
        self.dag, self.led, self.sk, self.pub, self.k1, self.k2, self.sealed = fresh()

    def test_baseline_verifies_and_opens(self):
        self.assertTrue(superproof.verify_seal(self.sealed, self.pub, self.led))
        self.assertEqual(cap.data_of(superproof.open_seal(self.sealed, self.k1, self.k2)), "secret-payload")

    def test_swapping_the_ciphertext_while_keeping_the_claimed_digest_is_caught(self):
        """Attack: replace ct_b64 with other bytes. The old verify only compared claimed digests and never hashed the ciphertext present."""
        s = copy.deepcopy(self.sealed)
        s["envelope"]["ct_b64"] = base64.b64encode(secrets.token_bytes(len(base64.b64decode(s["envelope"]["ct_b64"])))).decode()
        self.assertFalse(superproof.verify_seal(s, self.pub, self.led))

    def test_a_whole_envelope_from_another_seal_does_not_fit(self):
        other = fresh()[6]
        s = copy.deepcopy(self.sealed)
        s["envelope"] = other["envelope"]
        self.assertFalse(superproof.verify_seal(s, self.pub, self.led))

    def test_every_top_level_field_is_bound(self):
        for field, new in (("lineage_root", "0" * 64), ("top_root", "1" * 64), ("preset_hash", "2" * 64)):
            s = copy.deepcopy(self.sealed)
            s[field] = new
            self.assertFalse(superproof.verify_seal(s, self.pub, self.led), field)

    def test_a_weaker_proof_than_the_configuration_promised_is_refused(self):
        """Attack: claim a stronger preset while carrying a tier 0 proof."""
        from vega_superproof.seal import presets
        s = copy.deepcopy(self.sealed)
        s["preset"] = presets.preset_card("high_assurance")
        s["preset_hash"] = presets.preset_hash(s["preset"])
        self.assertFalse(superproof.verify_seal(s, self.pub, self.led))

    def test_the_signature_algorithm_comes_from_the_configuration_not_from_the_document(self):
        """Attack (algorithm confusion): name a registered permissive verifier inside the signature object."""
        class Yes:
            def sign(self, private, msg):
                return b"\x00"

            def verify(self, public, msg, sig):
                return True
        signature.register("evil-alg", Yes())
        try:
            s = copy.deepcopy(self.sealed)
            s["signature"] = {"alg": "evil-alg", "signature": "00", "public": None}
            self.assertFalse(superproof.verify_seal(s, self.pub, self.led))
        finally:
            signature._BACKENDS.pop("evil-alg", None)

    def test_wrong_public_key_and_foreign_ledger_fail(self):
        self.assertFalse(superproof.verify_seal(self.sealed, signature.new_ed25519()[1], self.led))
        t = pathlib.Path(tempfile.mkdtemp())
        other_led = Ledger([LocalBackend(t / "x.jsonl")])
        self.assertFalse(superproof.verify_seal(self.sealed, self.pub, other_led))

    def test_garbage_seals_return_false_never_raise(self):
        for bad in (None, {}, [], "x", dict(self.sealed, proof=None), dict(self.sealed, envelope=[]), dict(self.sealed, signature=5), {k: v for k, v in self.sealed.items() if k != "proof"}):
            self.assertFalse(superproof.verify_seal(bad, self.pub, self.led), repr(bad)[:50])

    def test_opening_with_wrong_keys_or_tampered_bytes_fails_cleanly(self):
        with self.assertRaises(InvalidTag):
            superproof.open_seal(self.sealed, layers.generate_key(), self.k2)
        s = copy.deepcopy(self.sealed)
        raw = bytearray(base64.b64decode(s["envelope"]["ct_b64"]))
        raw[0] ^= 1
        s["envelope"]["ct_b64"] = base64.b64encode(bytes(raw)).decode()
        with self.assertRaises(ValueError):
            superproof.open_seal(s, self.k1, self.k2)

    def test_malformed_envelopes_are_value_errors_not_other_exceptions(self):
        e = self.sealed["envelope"]
        for bad in (None, {}, [], dict(e, ct_b64="!!!"), dict(e, n1="zz"), dict(e, n1="00"), {k: v for k, v in e.items() if k != "aad_sha256"}, dict(e, version=2)):
            with self.assertRaises((ValueError, InvalidTag), msg=repr(bad)[:50]):
                layers.open_layers(bad, self.k1, self.k2, self.sealed["capsule_prefix_hash"].encode())

    def test_weak_or_equal_keys_are_refused_before_anything_is_recorded(self):
        n = len(self.dag.content.entries())
        sk, pub = signature.new_ed25519()
        c = cap.make("x", {"source": "u"})
        for a, b in ((b"\x00" * 32, layers.generate_key()), (b"a" * 32, layers.generate_key()), (self.k1, self.k1), (b"short", self.k2)):
            with self.assertRaises(ValueError):
                superproof.seal(c, a, b, sk, pub, self.dag, self.led)
        self.assertEqual(len(self.dag.content.entries()), n)

    def test_neither_plaintext_nor_key_material_reaches_the_record(self):
        text = "".join(p.read_text() for p in self.dag.content.paths + self.dag.locations.paths if p.exists())
        self.assertNotIn("secret-payload", text)
        self.assertNotIn(self.k1.hex(), text)
        self.assertNotIn(self.k2.hex(), text)
        self.assertNotIn(hashlib.sha256(self.k1).hexdigest(), text)        # key ids are domain-separated, not the plain hash of the key


if __name__ == "__main__":
    unittest.main()
