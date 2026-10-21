"""Regression tests (2026-10-20): the tier names must say what the built-in backends are. Tier 1 is a zero-knowledge proof of knowledge (Schnorr), tier 2 is hash-based
quantum-proof sealing. Neither is a SNARK or a STARK, and the code, error messages and presets must not say they are."""
import unittest

from vega_superproof.seal import builtin, presets, proof_tier1, proof_tier2, proof_tier3
from vega_superproof.seal.errors import TierUnavailable


class TierNames(unittest.TestCase):
    def setUp(self):
        for t in (proof_tier1, proof_tier2, proof_tier3):
            t._BACKEND = None

    def message(self, mod):
        with self.assertRaises(TierUnavailable) as cm:
            mod.require_prover()
        return str(cm.exception)

    def test_refusal_messages_name_what_the_tier_is(self):
        self.assertIn("privacy", self.message(proof_tier1))
        self.assertIn("quantum-proof", self.message(proof_tier2))
        self.assertIn("locked compute", self.message(proof_tier3))
        for mod in (proof_tier1, proof_tier2, proof_tier3):
            self.assertNotIn("SNARK", self.message(mod))
            self.assertNotIn("STARK", self.message(mod))

    def test_module_docstrings_state_the_built_in_backend(self):
        self.assertIn("Schnorr", proof_tier1.__doc__)
        self.assertIn("quantum-resistant", proof_tier2.__doc__)
        self.assertIn("none is shipped", proof_tier1.__doc__)
        self.assertIn("none is shipped", proof_tier2.__doc__)

    def test_preset_notes_point_to_the_backend_that_exists(self):
        self.assertIn("builtin.enable_privacy", presets.PRESETS["high_assurance"]["note"])
        self.assertIn("builtin.enable_quantum_proof", presets.PRESETS["maximum"]["note"])
        self.assertIn("refuses today", presets.PRESETS["maximum"]["note"])        # ml-dsa-65 is not built
        for name in ("high_assurance", "maximum"):
            self.assertNotIn("SNARK prover", presets.PRESETS[name]["note"])
            self.assertNotIn("a STARK prover", presets.PRESETS[name]["note"])

    def test_the_built_in_backends_match_the_names(self):
        self.assertTrue(hasattr(builtin, "enable_privacy") and hasattr(builtin, "enable_quantum_proof") and hasattr(builtin, "enable_locked_compute"))


class RotationIsSingleUseUnderRace(unittest.TestCase):
    """require_commitment ('already used for a rotation?') and commit_rotation ('record it') were two steps, so concurrent rotations could share one commitment or retire one key twice."""

    def setUp(self):
        import pathlib
        import tempfile
        from vega_custody.dag.dag import Dag
        from vega_custody.ledger.backend_local import LocalBackend
        from vega_custody.ledger.ledger import Ledger
        t = pathlib.Path(tempfile.mkdtemp())
        self.dag = Dag([t / "c.jsonl"], [t / "l.jsonl"])
        self.led = Ledger([LocalBackend(t / "led.jsonl")])
        self.n = 0

    def commitment(self):
        import time
        self.n += 1
        c = {"kind": "WCOMMIT", "device": "d", "surface": "s", "action": "rotate_keys", "action_hash": f"{self.n:064x}", "expiry": int(time.time()) + 300, "nonce_sha256": f"{self.n + 50:064x}"}
        self.led.mint(c)
        return c

    def race(self, jobs):
        import threading
        from vega_superproof.seal import scrambler
        gate, out, lock = threading.Barrier(len(jobs)), [], threading.Lock()

        def go(job):
            gate.wait()
            try:
                scrambler.rotate(*job)
                r = "rotated"
            except scrambler.RotationRefused:
                r = "refused"
            with lock:
                out.append(r)
        ts = [threading.Thread(target=go, args=(j,)) for j in jobs]
        for t in ts:
            t.start()
        for t in ts:
            t.join(60)
        return sorted(out)

    def test_one_commitment_cannot_rotate_two_different_keys_at_once(self):
        from vega_superproof.seal import layers, scrambler
        for _ in range(15):
            c = self.commitment()
            jobs = []
            for _k in range(2):
                dek, old, new = layers.generate_key(), layers.generate_key(), layers.generate_key()
                jobs.append((scrambler.wrap(dek, old), old, new, self.led, self.dag, c))
            self.assertEqual(self.race(jobs), ["refused", "rotated"])

    def test_one_key_cannot_be_retired_twice_at_once(self):
        from vega_superproof.seal import layers, scrambler
        for _ in range(15):
            dek, old = layers.generate_key(), layers.generate_key()
            wrapped = scrambler.wrap(dek, old)
            jobs = [(wrapped, old, layers.generate_key(), self.led, self.dag, self.commitment()) for _ in range(2)]
            self.assertEqual(self.race(jobs), ["refused", "rotated"])

    def test_junk_in_place_of_a_commitment_is_a_refusal_not_a_crash(self):
        from vega_superproof.seal import layers, scrambler
        dek, old, new = layers.generate_key(), layers.generate_key(), layers.generate_key()
        w = scrambler.wrap(dek, old)
        for junk in (None, "text", 5, [], {"action": "rotate_keys", "expiry": "soon"}, {"action": "rotate_keys", "expiry": None}):
            with self.assertRaises(scrambler.RotationRefused, msg=repr(junk)):
                scrambler.rotate(w, old, new, self.led, self.dag, junk)


if __name__ == "__main__":
    unittest.main()
