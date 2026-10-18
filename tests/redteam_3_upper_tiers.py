"""Red team 3: the upper tiers - privacy (zk.py), quantum-proof (hashsig.py, disclosure.py), locked compute with updating encryption (lwe.py), rotation.py.
Run as: python tests/redteam_3_upper_tiers.py"""
import copy
import json
import os
import pathlib
import secrets
import tempfile
import threading
import unittest

from vega_custody.capsule import capsule as cap
from vega_custody.dag.dag import Dag
from vega_custody.ledger.backend_local import LocalBackend
from vega_custody.ledger.ledger import Ledger
from vega_superproof.seal import builtin, disclosure, ec, hashsig, lwe, proof_tier1, proof_tier2, proof_tier3, rotation, signature, superproof, zk
from vega_superproof.seal.errors import TierUnavailable


def world():
    t = pathlib.Path(tempfile.mkdtemp())
    return t, Dag([t / "c.jsonl"], [t / "l.jsonl"]), Ledger([LocalBackend(t / "led.jsonl")])


class Curve(unittest.TestCase):
    def test_constants_and_encoding(self):
        self.assertTrue(ec.on_curve(ec.G) and ec.on_curve(ec.H))
        self.assertIsNone(ec.mul(ec.N, ec.G))
        self.assertNotEqual(ec.H, ec.G)
        for k in (1, 2, 12345, ec.N - 1):
            p = ec.mul(k, ec.G)
            self.assertEqual(ec.decode(ec.encode(p)), p)
        self.assertEqual(ec.decode(ec.encode(None)), None)

    def test_bad_points_are_refused(self):
        for bad in (b"", b"\x02" * 5, b"\x05" + b"\x00" * 32, b"\x02" + (ec.P).to_bytes(32, "big"), b"\x02" + (5).to_bytes(32, "big"), "text", None):
            with self.assertRaises(ec.ECError):
                ec.decode(bad)


class Knowledge(unittest.TestCase):
    def test_proof_of_knowledge_binds_to_key_and_message(self):
        x = secrets.randbelow(ec.N - 1) + 1
        pr = zk.prove_knowledge(x, b"m")
        self.assertTrue(zk.verify_knowledge(zk.public_of(x), b"m", pr))
        self.assertFalse(zk.verify_knowledge(zk.public_of(x), b"other", pr))
        self.assertFalse(zk.verify_knowledge(zk.public_of(x + 1), b"m", pr))
        bad = dict(pr, s="%064x" % ((int(pr["s"], 16) + 1) % ec.N))
        self.assertFalse(zk.verify_knowledge(zk.public_of(x), b"m", bad))
        for junk in (None, {}, {"R": "00", "s": "00"}, {"R": pr["R"], "s": "zz"}, {"R": pr["R"], "s": "%064x" % ec.N}, {"R": ec.encode(None).hex(), "s": pr["s"]}):
            self.assertFalse(zk.verify_knowledge(zk.public_of(x), b"m", junk))
        self.assertFalse(zk.verify_knowledge(ec.encode(None), b"m", pr))
        s5 = 5
        trivial = {"R": ec.encode(ec.mul(s5, ec.G)).hex(), "s": "%064x" % s5}      # anyone can 'prove' knowledge of the log of the point at infinity
        self.assertFalse(zk.verify_knowledge(ec.encode(None), b"m", trivial))


class Commitments(unittest.TestCase):
    def test_commitments_open_hide_and_refuse_nonsense(self):
        c1, r1 = zk.commit(500)
        c2, r2 = zk.commit(500)
        self.assertNotEqual(c1, c2)                                           # same number, different blinding: nothing to compare
        self.assertTrue(zk.opens_to(c1, 500, r1))
        self.assertFalse(zk.opens_to(c1, 501, r1))
        self.assertFalse(zk.opens_to(c1, 500, r2))
        self.assertFalse(zk.opens_to(b"junk", 500, r1))
        for bad in (-1, True, 1.5, "5", ec.N):
            with self.assertRaises(zk.ZKRefused):
                zk.commit(bad)


class Range(unittest.TestCase):
    def test_a_value_in_range_proves_and_verifies(self):
        c, r = zk.commit(200)
        p = zk.prove_range(200, r, 8, b"ctx")
        self.assertTrue(zk.verify_range(c, 8, p, b"ctx"))

    def test_no_honest_proof_exists_outside_the_range(self):
        c, r = zk.commit(256)
        with self.assertRaises(zk.ZKRefused):
            zk.prove_range(256, r, 8)
        with self.assertRaises(zk.ZKRefused):
            zk.prove_range(-1, r, 8)
        for bits in (0, 65, True, "8"):
            with self.assertRaises(zk.ZKRefused):
                zk.prove_range(1, r, bits)

    def test_proofs_do_not_move_between_commitments_contexts_or_sizes(self):
        c, r = zk.commit(77)
        p = zk.prove_range(77, r, 8, b"ctx")
        c_other, _ = zk.commit(77)
        self.assertFalse(zk.verify_range(c_other, 8, p, b"ctx"))              # another commitment to the same number
        self.assertFalse(zk.verify_range(c, 8, p, b"other context"))
        self.assertFalse(zk.verify_range(c, 9, p, b"ctx"))
        self.assertFalse(zk.verify_range(c, 8, dict(p, bits=9), b"ctx"))

    def test_tampering_any_part_fails(self):
        c, r = zk.commit(99)
        p = zk.prove_range(99, r, 8, b"ctx")
        for i in (0, 3, 7):
            q = copy.deepcopy(p)
            q["bit_proofs"][i]["s0"] = "%064x" % ((int(q["bit_proofs"][i]["s0"], 16) + 1) % ec.N)
            self.assertFalse(zk.verify_range(c, 8, q, b"ctx"))
            q = copy.deepcopy(p)
            q["bit_proofs"][i]["c0"] = "%064x" % ((int(q["bit_proofs"][i]["c0"], 16) + 1) % ec.N)
            self.assertFalse(zk.verify_range(c, 8, q, b"ctx"))
        q = copy.deepcopy(p)
        q["bit_commitments"][0], q["bit_commitments"][1] = q["bit_commitments"][1], q["bit_commitments"][0]
        self.assertFalse(zk.verify_range(c, 8, q, b"ctx"))                    # bits swapped: the weighted sum no longer matches
        q = copy.deepcopy(p)
        q["bit_proofs"] = q["bit_proofs"][:-1]
        self.assertFalse(zk.verify_range(c, 8, q, b"ctx"))
        for junk in (None, {}, {"bits": 8}, "x", {"bits": 8, "bit_commitments": [], "bit_proofs": []}):
            self.assertFalse(zk.verify_range(c, 8, junk, b"ctx"))

    def test_a_bit_that_is_not_0_or_1_cannot_be_proved(self):
        r = secrets.randbelow(ec.N - 1) + 1
        two = ec.add(ec.mul(2, ec.G), ec.mul(r, ec.H))                         # a 'bit' that commits to 2
        for claimed in (0, 1):
            pr = zk._or_prove_full(claimed, r, two, b"ctx", 0)                  # a lying prover runs the honest algorithm anyway
            self.assertFalse(zk._or_verify_full(two, b"ctx", 0, pr))
        one = ec.add(ec.mul(1, ec.G), ec.mul(r, ec.H))
        self.assertTrue(zk._or_verify_full(one, b"ctx", 0, zk._or_prove_full(1, r, one, b"ctx", 0)))
        self.assertFalse(zk._or_verify_full(one, b"ctx", 1, zk._or_prove_full(1, r, one, b"ctx", 0)))   # position is in the hash


class AtLeast(unittest.TestCase):
    def test_threshold_edge_and_refusals(self):
        for v, t, ok in ((3000, 3000, True), (3000, 2999, True), (3000, 3001, False), (0, 0, True)):
            c, r = zk.commit(v)
            if ok:
                p = zk.prove_at_least(v, r, t, 8, b"c")
                self.assertTrue(zk.verify_at_least(c, t, 8, p, b"c"), (v, t))
            else:
                with self.assertRaises(zk.ZKRefused):
                    zk.prove_at_least(v, r, t, 8, b"c")

    def test_the_proof_is_for_this_threshold_commitment_and_context_only(self):
        c, r = zk.commit(500)
        p = zk.prove_at_least(500, r, 400, 8, b"c")
        self.assertFalse(zk.verify_at_least(c, 401, 8, p, b"c"))
        self.assertFalse(zk.verify_at_least(c, 399, 8, p, b"c"))
        self.assertFalse(zk.verify_at_least(c, 400, 8, p, b"d"))
        self.assertFalse(zk.verify_at_least(zk.commit(500)[0], 400, 8, p, b"c"))
        self.assertFalse(zk.verify_at_least(c, 400, 8, dict(p, threshold=399), b"c"))
        forged = copy.deepcopy(p)
        forged["threshold"] = 600
        self.assertFalse(zk.verify_at_least(c, 600, 8, forged, b"c"))         # claiming a higher bar with the same proof
        for bad in (-1, True, "4"):
            self.assertFalse(zk.verify_at_least(c, bad, 8, p, b"c"))

    def test_a_value_below_the_bar_cannot_pass_by_wrapping_around(self):
        c, r = zk.commit(10)
        with self.assertRaises(zk.ZKRefused):
            zk.prove_at_least(10, r, 20, 8)
        shifted_range = zk.prove_range(246, r, 8, b"AT-LEAST|20|")                # 246 = 10 - 20 + 256: wrong shift, so it cannot match C - 20G
        self.assertFalse(zk.verify_at_least(c, 20, 8, {"threshold": 20, "range": shifted_range}, b""))


class Attestation(unittest.TestCase):
    def test_who_vouches_for_the_hidden_number(self):
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        from cryptography.hazmat.primitives import serialization
        sk = Ed25519PrivateKey.generate()
        pub = sk.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        c, _ = zk.commit(4200)
        sig = zk.attest(sk, c, "monthly_income")
        self.assertTrue(zk.verify_attestation(pub, c, "monthly_income", sig))
        self.assertFalse(zk.verify_attestation(pub, c, "monthly_rent", sig))
        self.assertFalse(zk.verify_attestation(pub, zk.commit(4200)[0], "monthly_income", sig))
        other = Ed25519PrivateKey.generate().public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        self.assertFalse(zk.verify_attestation(other, c, "monthly_income", sig))
        for junk in ("", "zz", None, "00" * 64):
            self.assertFalse(zk.verify_attestation(pub, c, "monthly_income", junk))
        for bad in ("", "a|b", None):
            with self.assertRaises(zk.ZKRefused):
                zk.attest(sk, c, bad)


class HashSignature(unittest.TestCase):
    def test_sign_verify_and_tamper(self):
        s = hashsig.Signer(4)
        g = s.sign(b"hello")
        self.assertTrue(hashsig.verify(s.public, b"hello", g))
        self.assertFalse(hashsig.verify(s.public, b"hellp", g))
        for pos in (0, 3, 4, 40, 500, len(g) - 1):
            bad = bytearray(g)
            bad[pos] ^= 1
            self.assertFalse(hashsig.verify(s.public, b"hello", bytes(bad)), pos)
        self.assertFalse(hashsig.verify(hashsig.Signer(4).public, b"hello", g))
        self.assertFalse(hashsig.verify(s.public, b"hello", g[:-32]))
        self.assertFalse(hashsig.verify(s.public, b"hello", g + b"\x00" * 32))
        self.assertFalse(hashsig.verify(s.public, b"hello", g + b"\x00"))
        self.assertFalse(hashsig.verify(s.public, b"hello", g, height=5))
        self.assertTrue(hashsig.verify(s.public, b"hello", g, height=4))
        for junk in (None, "x", b"", b"\x00" * 64):
            self.assertFalse(hashsig.verify(s.public, b"hello", junk))
            self.assertFalse(hashsig.verify(junk, b"hello", g))

    def test_one_time_keys_are_used_once_and_then_run_out(self):
        s = hashsig.Signer(2)
        sigs = [s.sign(b"m%d" % i) for i in range(4)]
        self.assertEqual([int.from_bytes(g[:4], "big") for g in sigs], [0, 1, 2, 3])
        self.assertTrue(all(hashsig.verify(s.public, b"m%d" % i, g) for i, g in enumerate(sigs)))
        self.assertEqual(s.remaining, 0)
        with self.assertRaises(hashsig.HashSigError):
            s.sign(b"one too many")
        self.assertFalse(hashsig.verify(s.public, b"m0", sigs[1]))             # a signature is for one message at one index

    def test_the_index_is_saved_before_the_signature_and_never_goes_back(self):
        t = pathlib.Path(tempfile.mkdtemp()) / "state.json"
        seed = secrets.token_bytes(32)
        s1 = hashsig.Signer(3, seed=seed, state_path=t)
        s1.sign(b"a")
        s1.sign(b"b")
        s2 = hashsig.Signer(3, seed=seed, state_path=t)                          # a restart
        self.assertEqual(s2.remaining, 6)
        self.assertEqual(int.from_bytes(s2.sign(b"c")[:4], "big"), 2)
        t.write_text("not json")
        with self.assertRaises(hashsig.HashSigError):
            hashsig.Signer(3, seed=seed, state_path=t)                           # a damaged state file blocks signing: it never guesses
        t.write_text(json.dumps({"root": "00" * 32, "next": 0}))
        with self.assertRaises(hashsig.HashSigError):
            hashsig.Signer(3, seed=seed, state_path=t)                           # a state file of another key
        t.write_text(json.dumps({"root": hashsig.Signer(3, seed=seed).root.hex(), "next": -4}))
        with self.assertRaises(hashsig.HashSigError):
            hashsig.Signer(3, seed=seed, state_path=t)

    def test_threads_never_share_an_index(self):
        s = hashsig.Signer(5)
        out = []

        def work():
            out.append(int.from_bytes(s.sign(b"x")[:4], "big"))
        th = [threading.Thread(target=work) for _ in range(20)]
        [x.start() for x in th]
        [x.join() for x in th]
        self.assertEqual(sorted(out), list(range(20)))

    def test_the_checksum_digits_stop_a_forger_from_only_moving_chains_forward(self):
        self.assertEqual(hashsig._digits(bytes(32)), [0] * 64 + [3, 12, 0])           # all-zero digits: checksum 960
        self.assertEqual(hashsig._digits(bytes([255]) * 32), [15] * 64 + [0, 0, 0])        # all-maximum digits: checksum 0
        self.assertEqual(len(hashsig._digits(secrets.token_bytes(32))), hashsig.LEN)

    def test_bad_parameters(self):
        for h in (0, 11, True, "4", None):
            with self.assertRaises(hashsig.HashSigError):
                hashsig.Signer(h)
        with self.assertRaises(hashsig.HashSigError):
            hashsig.Signer(3, seed=b"short")
        with self.assertRaises(hashsig.HashSigError):
            hashsig.Signer(3).sign("not bytes")

    def test_it_plugs_in_as_the_seal_signature(self):
        hashsig.register()
        hashsig.register()                                                      # idempotent
        s = hashsig.Signer(3)
        root = "ab" * 32
        sig = signature.sign_root(s, root, hashsig.ALG, s.public)
        self.assertTrue(signature.verify_root(sig, root, s.public, expected_alg=hashsig.ALG))
        self.assertFalse(signature.verify_root(sig, "cd" * 32, s.public, expected_alg=hashsig.ALG))
        self.assertFalse(signature.verify_root(sig, root, s.public, expected_alg="ed25519"))
        with self.assertRaises(hashsig.HashSigError):
            hashsig.HashSigBackend().sign("not a signer", b"x")


class Disclosure(unittest.TestCase):
    def setUp(self):
        self.fields = {"name": "Alex", "income": 4200, "city": "Oslo", "dob": "1990-01-01", "flag": True}
        self.root, self.op = disclosure.commit_record(self.fields)

    def test_show_some_fields_and_only_those(self):
        pr = disclosure.disclose(self.op, ["income", "city"])
        self.assertEqual(disclosure.verify_disclosure(self.root, pr), {"income": 4200, "city": "Oslo"})
        blob = json.dumps(pr)
        for hidden in ("Alex", "1990-01-01", "dob"):
            self.assertNotIn(hidden, blob)

    def test_the_root_hides_values_names_and_exact_count(self):
        r2, _ = disclosure.commit_record(self.fields)
        self.assertNotEqual(self.root, r2)                                      # fresh salts: the same record gives an unlinkable root
        self.assertEqual(disclosure.disclose(self.op, ["name"])["size"], 8)       # 5 fields -> a bucket of 8

    def test_tampering_and_forgery_fail(self):
        pr = disclosure.disclose(self.op, ["income"])
        for edit in (lambda p: p["fields"][0].update(value=9999), lambda p: p["fields"][0].update(name="salary"), lambda p: p["fields"][0].update(salt="00" * 32),
                     lambda p: p["fields"][0].update(pos=p["fields"][0]["pos"] ^ 1), lambda p: p["fields"][0]["path"].pop(), lambda p: p.update(size=16),
                     lambda p: p.update(size=3), lambda p: p.update(size=True), lambda p: p["fields"].append(p["fields"][0])):
            q = copy.deepcopy(pr)
            edit(q)
            self.assertIsNone(disclosure.verify_disclosure(self.root, q))
        self.assertIsNone(disclosure.verify_disclosure("00" * 32, pr))
        for junk in (None, {}, {"size": 8}, {"size": 8, "fields": [{}]}, "x"):
            self.assertIsNone(disclosure.verify_disclosure(self.root, junk))

    def test_bad_input_is_refused(self):
        for bad in ({}, [], None, {"": 1}, {"a": object()}, {"a": float("nan")}, {"x" * 300: 1}, {1: 2}):
            with self.assertRaises(disclosure.DisclosureRefused):
                disclosure.commit_record(bad)
        with self.assertRaises(disclosure.DisclosureRefused):
            disclosure.disclose(self.op, ["nope"])


class LockedCompute(unittest.TestCase):
    def setUp(self):
        self.p = lwe.Params(n=32)
        self.h = lwe.KeyHolder(self.p)

    def test_add_sub_scale_dot_on_locked_numbers(self):
        h, p = self.h, self.p
        c = [h.encrypt(v) for v in (10, 20, 30)]
        self.assertEqual(h.decrypt(lwe.total(p, c)), 60)
        self.assertEqual(h.decrypt(lwe.sub(p, c[2], c[0])), 20)
        self.assertEqual(h.decrypt(lwe.scale(p, c[1], 7)), 140)
        self.assertEqual(h.decrypt(lwe.dot(p, c, [1, 2, 3])), 10 + 40 + 90)
        self.assertEqual(h.decrypt(lwe.sub(p, c[0], c[2])), (10 - 30) % p.t)       # wraps modulo the plaintext size, like any modular arithmetic
        self.assertEqual(h.decrypt(h.encrypt(p.t - 1)), p.t - 1)

    def test_the_evaluator_needs_no_key(self):
        h, p = self.h, self.p
        c = h.encrypt(5)
        self.assertEqual(h.decrypt(lwe.scale(p, c, 3)), 15)
        self.assertNotEqual(c.b, 5)
        self.assertNotIn(5, c.a)

    def test_updating_encryption_moves_ciphertexts_without_decrypting(self):
        h, p = self.h, self.p
        total = lwe.dot(p, [h.encrypt(10), h.encrypt(20)], [3, 4])
        new, sk = h.rotate()
        moved = lwe.switch(p, total, sk)
        self.assertEqual((new.epoch, moved.epoch), (1, 1))
        self.assertGreater(moved.noise, total.noise)                           # the switch adds noise and the bound says so
        self.assertEqual(new.decrypt(moved), 110)
        with self.assertRaises(lwe.LweError):
            h.decrypt(total)                                                    # the old key is wiped
        with self.assertRaises(lwe.LweError):
            h.encrypt(1)
        with self.assertRaises(lwe.LweError):
            new.decrypt(total)                                                  # an old-epoch ciphertext is refused by the new key
        newer, sk2 = new.rotate()
        self.assertEqual(newer.decrypt(lwe.switch(p, moved, sk2)), 110)         # and again
        with self.assertRaises(lwe.LweError):
            lwe.switch(p, total, sk2)                                           # the wrong switch key for that epoch

    def test_epochs_and_parameter_sets_never_mix(self):
        h, p = self.h, self.p
        new, sk = h.rotate()
        a, b = new.encrypt(1), self.h if False else None
        old_style = lwe.Ciphertext(p.id, 0, [0] * p.n, 0, 0)
        with self.assertRaises(lwe.LweError):
            lwe.add(p, a, old_style)
        other = lwe.Params(n=64)
        with self.assertRaises(lwe.LweError):
            lwe.add(p, a, lwe.KeyHolder(other).encrypt(1))
        with self.assertRaises(lwe.LweError):
            lwe.switch(other, a, sk)

    def test_the_noise_budget_refuses_instead_of_answering_wrong(self):
        h, p = self.h, self.p
        c = h.encrypt(1)
        with self.assertRaises(lwe.NoiseBudgetExhausted):
            for _ in range(40):
                c = lwe.scale(p, c, p.t - 1)
        with self.assertRaises(lwe.NoiseBudgetExhausted):
            h.decrypt(lwe.Ciphertext(p.id, h.epoch, [0] * p.n, 0, p.limit))

    def test_inputs_are_checked(self):
        h, p = self.h, self.p
        for bad in (-1, p.t, True, 1.5, "1", None):
            with self.assertRaises(lwe.LweError):
                h.encrypt(bad)
        c = h.encrypt(1)
        for bad in (-1, p.t, True, 1.5):
            with self.assertRaises(lwe.LweError):
                lwe.scale(p, c, bad)
        with self.assertRaises(lwe.LweError):
            lwe.total(p, [])
        with self.assertRaises(lwe.LweError):
            lwe.dot(p, [c], [1, 2])
        for bad in ((4, 48, 16, 8), (32, 70, 16, 8), (32, 48, 45, 8), (32, 48, 16, 20), (True, 48, 16, 8)):
            with self.assertRaises(lwe.LweError):
                lwe.Params(*bad)

    def test_ciphertexts_survive_json_and_malformed_ones_are_refused(self):
        h, p = self.h, self.p
        c = h.encrypt(42)
        back = lwe.Ciphertext.from_dict(json.loads(json.dumps(c.to_dict())), p)
        self.assertEqual(h.decrypt(back), 42)
        d = c.to_dict()
        for edit in (lambda x: x.update(a=x["a"][:-1]), lambda x: x.update(b=p.q), lambda x: x.update(epoch=-1), lambda x: x.update(params="other"), lambda x: x.update(noise=-1),
                     lambda x: x.update(a=[True] * p.n), lambda x: x.pop("b")):
            q = copy.deepcopy(d)
            edit(q)
            with self.assertRaises(lwe.LweError):
                lwe.Ciphertext.from_dict(q, p)
        with self.assertRaises(lwe.LweError):
            lwe.Ciphertext.from_dict("x", p)

    def test_the_default_parameters_are_marked_and_small_ones_are_insecure(self):
        self.assertTrue(lwe.Params(n=32).insecure)
        self.assertFalse(lwe.Params().insecure)

    def test_the_backend_plugs_into_the_fhe_interface(self):
        h, p = self.h, self.p
        be = lwe.LweBackend(p)
        c = [h.encrypt(2), h.encrypt(3)]
        self.assertEqual(h.decrypt(be.evaluate("add", c)), 5)
        self.assertEqual(h.decrypt(be.evaluate("sum", c)), 5)
        self.assertEqual(h.decrypt(be.evaluate("sub", [c[1], c[0]])), 1)
        self.assertEqual(h.decrypt(be.evaluate("scale:4", [c[0]])), 8)
        self.assertEqual(h.decrypt(be.evaluate("dot:2,5", c)), 19)
        for bad in ("multiply", "scale:x", "add", "dot:1,2"):
            with self.assertRaises((lwe.LweError, ValueError)):
                be.evaluate(bad, c[:1])


class UpperTierSeals(unittest.TestCase):
    def setUp(self):
        self.t, self.dag, self.led = world()
        self.k1, self.k2 = secrets.token_bytes(32), secrets.token_bytes(32)
        self.c = cap.make("sealed text", {"source": "user"})
        self.ed_sk, self.ed_pub = signature.new_ed25519()
        self.hs = hashsig.Signer(4)

    def test_a_tier_nobody_enabled_fails_closed_and_writes_nothing(self):
        for mod in (proof_tier1, proof_tier2, proof_tier3):
            mod._BACKEND = None
        for preset in ("private", "quantum_proof", "locked_compute"):
            before = len(self.dag.content.entries())
            with self.assertRaises(TierUnavailable):
                superproof.seal(self.c, self.k1, self.k2, self.hs, self.hs.public, self.dag, self.led, preset)
            self.assertEqual(len(self.dag.content.entries()), before)

    def test_privacy_tier(self):
        b = builtin.enable_privacy(secrets.randbelow(ec.N - 1) + 1, replace=True)
        s = superproof.seal(self.c, self.k1, self.k2, self.ed_sk, self.ed_pub, self.dag, self.led, "private")
        self.assertEqual(s["proof"]["tier"], 1)
        self.assertTrue(superproof.verify_seal(s, self.ed_pub, self.led, accept_tiers=(1,)))
        self.assertFalse(superproof.verify_seal(s, self.ed_pub, self.led, accept_tiers=(2, 3)))
        self.assertEqual(superproof.open_seal(s, self.k1, self.k2)["prefix_hash"], self.c["prefix_hash"])
        stmt = s["proof"]["statement"]
        other = dict(stmt, capsule_sha256="00" * 32)
        self.assertFalse(b.verify(other, bytes.fromhex(s["proof"]["proof_hex"])))        # bound to this exact seal
        self.assertNotIn(str(b._x), json.dumps(s))                                         # the secret is nowhere in the record

    def test_quantum_proof_tier_uses_only_quantum_resistant_parts(self):
        builtin.enable_quantum_proof(replace=True)
        s = superproof.seal(self.c, self.k1, self.k2, self.hs, self.hs.public, self.dag, self.led, "quantum_proof")
        self.assertEqual((s["proof"]["tier"], s["signature"]["alg"]), (2, hashsig.ALG))
        self.assertTrue(superproof.verify_seal(s, self.hs.public, self.led, accept_tiers=(2, 3), require_signature=hashsig.ALG))
        self.assertFalse(superproof.verify_seal(s, self.hs.public, self.led, accept_tiers=(0,)))
        self.assertFalse(superproof.verify_seal(s, self.hs.public, self.led, require_signature="ed25519"))
        bad = copy.deepcopy(s)
        sig = bytearray(bytes.fromhex(bad["signature"]["signature"]))
        sig[50] ^= 1
        bad["signature"]["signature"] = bytes(sig).hex()
        self.assertFalse(superproof.verify_seal(bad, self.hs.public, self.led))

    def test_a_classical_seal_cannot_pass_as_quantum_proof(self):
        s = superproof.seal(self.c, self.k1, self.k2, self.ed_sk, self.ed_pub, self.dag, self.led, "standard")
        self.assertTrue(superproof.verify_seal(s, self.ed_pub, self.led))
        self.assertFalse(superproof.verify_seal(s, self.ed_pub, self.led, accept_tiers=(2, 3)))
        self.assertFalse(superproof.verify_seal(s, self.ed_pub, self.led, require_signature=hashsig.ALG))

    def test_a_quantum_proof_attestation_naming_a_weak_part_is_refused(self):
        b = builtin.QuantumBackend()
        stmt = {"x": 1}
        good = json.loads(b.prove(stmt))
        for edit in (lambda d: d.update(layers=["aes-128-gcm"]), lambda d: d.update(hash="md5"), lambda d: d.update(signature="ed25519"), lambda d: d.update(statement="00" * 32)):
            d = dict(good)
            edit(d)
            self.assertFalse(b.verify(stmt, json.dumps(d).encode()))
        self.assertTrue(b.verify(stmt, b.prove(stmt)))
        self.assertFalse(b.verify({"x": 2}, b.prove(stmt)))
        for junk in (b"", b"[]", b"not json", b"\xff\xfe"):
            self.assertFalse(b.verify(stmt, junk))

    def test_locked_compute_tier_names_the_generation_of_the_encryption(self):
        p = lwe.Params(n=32)
        builtin.enable_locked_compute(p.id, 3, "ab" * 32, replace=True)
        s = superproof.seal(self.c, self.k1, self.k2, self.hs, self.hs.public, self.dag, self.led, "locked_compute")
        self.assertEqual(s["proof"]["tier"], 3)
        self.assertTrue(superproof.verify_seal(s, self.hs.public, self.led, accept_tiers=(3,)))
        att = json.loads(bytes.fromhex(s["proof"]["proof_hex"]))
        self.assertEqual((att["epoch"], att["he_params"], att["rotation_log"]), (3, p.id, "ab" * 32))

    def test_privacy_secret_must_be_a_valid_scalar(self):
        for bad in (0, -1, ec.N, True, "x", None):
            with self.assertRaises(ValueError):
                builtin.PrivacyBackend(bad)


class Rotation(unittest.TestCase):
    def setUp(self):
        self.t, self.dag, self.led = world()
        self.c = cap.make("rotate me", {"source": "user"})
        self.hs = hashsig.Signer(4)
        builtin.enable_quantum_proof(replace=True)

    def test_the_ratchet_only_moves_forward_and_keys_differ_by_epoch_and_layer(self):
        r = rotation.KeyRatchet(secrets.token_bytes(32))
        k1a, k2a = r.current()
        self.assertNotEqual(k1a, k2a)
        self.assertEqual(r.advance(), 1)
        k1b, k2b = r.current()
        self.assertTrue(len({k1a, k2a, k1b, k2b}) == 4)
        r2 = rotation.KeyRatchet(secrets.token_bytes(32))
        self.assertNotEqual(r2.current(), (k1a, k2a))
        for bad in (b"short", None, bytes(32), "x" * 32):
            with self.assertRaises(ValueError):
                rotation.KeyRatchet(bad)

    def test_reseal_moves_the_record_to_new_keys_and_links_the_old_root(self):
        r = rotation.KeyRatchet(secrets.token_bytes(32))
        o1, o2 = r.current()
        s_old = superproof.seal(self.c, o1, o2, self.hs, self.hs.public, self.dag, self.led, "quantum_proof")
        r.advance()
        n1, n2 = r.current()
        s_new = rotation.reseal(s_old, o1, o2, n1, n2, self.hs, self.hs.public, self.dag, self.led)
        self.assertEqual(superproof.open_seal(s_new, n1, n2)["prefix_hash"], self.c["prefix_hash"])
        with self.assertRaises(Exception):
            superproof.open_seal(s_new, o1, o2)                                   # the old keys no longer open the new seal
        self.assertTrue(superproof.verify_seal(s_new, self.hs.public, self.led, accept_tiers=(2,)))
        self.assertTrue(superproof.verify_seal(s_old, self.hs.public, self.led, accept_tiers=(2,)))     # the old seal stays valid as history
        rec = [e for e in self.dag.content.entries() if e["kind"] == "SEAL_ROTATED"]
        self.assertEqual(rec[0]["payload"]["old_top_root"], s_old["top_root"])
        self.assertEqual(rec[0]["payload"]["new_top_root"], s_new["top_root"])
        self.assertNotEqual(s_old["top_root"], s_new["top_root"])
        self.assertTrue(self.dag.verify()[0])

    def test_reseal_refuses_the_same_keys_and_wrong_old_keys(self):
        o1, o2 = secrets.token_bytes(32), secrets.token_bytes(32)
        s = superproof.seal(self.c, o1, o2, self.hs, self.hs.public, self.dag, self.led, "quantum_proof")
        with self.assertRaises(Exception):
            rotation.reseal(s, o1, o2, o1, o2, self.hs, self.hs.public, self.dag, self.led)
        with self.assertRaises(Exception):
            rotation.reseal(s, secrets.token_bytes(32), o2, secrets.token_bytes(32), secrets.token_bytes(32), self.hs, self.hs.public, self.dag, self.led)


if __name__ == "__main__":
    unittest.main()
