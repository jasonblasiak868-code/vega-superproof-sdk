"""Mutation check for the upper tiers: remove each protection in a COPY of the package and confirm redteam_3_upper_tiers.py fails.
Run: source SDK_FAMILY/env_family.sh; python tests/mutations_upper.py"""
import os, pathlib, shutil, subprocess, sys, tempfile

REPO = pathlib.Path(__file__).resolve().parent.parent
Z, HS, D, L, B, SP, R = "seal/zk.py", "seal/hashsig.py", "seal/disclosure.py", "seal/lwe.py", "seal/builtin.py", "seal/superproof.py", "seal/rotation.py"
MUTATIONS = [
    ("schnorr binds the message", Z, 'c = ec.hash_to_scalar(b"VEGA-SCHNORR-1", ec.encode(Y), ec.encode(R), message)\n        return ec.mul(s, ec.G)', 'c = ec.hash_to_scalar(b"VEGA-SCHNORR-1", ec.encode(Y), ec.encode(R), b"")\n        return ec.mul(s, ec.G)'),
    ("schnorr refuses the point at infinity", Z, "if Y is ec.INF or R is ec.INF:", "if False:"),
    ("bit commitments must add up to the commitment", Z, "return total == C", "return True"),
    ("bit count is checked", Z, 'if proof["bits"] != bits or len(proof["bit_commitments"]) != bits or len(proof["bit_proofs"]) != bits:', "if False:"),
    ("every bit proof is checked", Z, 'if not _or_verify_full(Ci, context, i, proof["bit_proofs"][i]):', "if False:"),
    ("the bit position is in the challenge", Z, 'c_total = ec.hash_to_scalar(b"VEGA-BIT-2", ctx, idx, ec.encode(C), ec.encode(R0), ec.encode(R1))', 'c_total = ec.hash_to_scalar(b"VEGA-BIT-2", ctx, 0, ec.encode(C), ec.encode(R0), ec.encode(R1))'),
    ("at-least shifts the commitment", Z, "shifted = ec.encode(ec.add(_pt(commitment), ec.neg(ec.mul(threshold, ec.G))))", "shifted = commitment"),
    ("at-least threshold must match", Z, 'if proof["threshold"] != threshold or', "if False or"),
    ("attestation binds the label", Z, 'return b"VEGA-ATTEST-1|" + label.encode("utf-8") + b"|" + bytes(commitment)', 'return b"VEGA-ATTEST-1|" + bytes(commitment)'),
    ("range prover refuses out-of-range values", Z, " or not 0 <= value < (1 << bits):", ":"),
    ("signature index saved before signing", HS, "if self._state:\n                self._save()", "pass"),
    ("keys run out", HS, "if self._next >= (1 << self.height):", "if False:"),
    ("winternitz checksum", HS, "return d + [(csum >> 8) & 15, (csum >> 4) & 15, csum & 15]", "return d"),
    ("root comparison", HS, "return hmac.compare_digest(node, root)", "return True"),
    ("duplicate fields refused", D, "if name in shown or pos in seen_pos:", "if False:"),
    ("path length checked", D, ' or len(f["path"]) != depth', ""),
    ("root is recomputed", D, "if node.hex() != root_hex:", "if False:"),
    ("bucket size shape", D, " or size & (size - 1)", ""),
    ("noise budget guard", L, "if noise >= p.limit:", "if False:"),
    ("decrypt checks the epoch", L, "if ct.params_id != p.id or ct.epoch != self.epoch:", "if False:"),
    ("evaluator refuses mixed epochs", L, "if c.params_id != p.id or c.epoch != first.epoch:", "if False:"),
    ("rotation wipes the old key", L, "self._alive = False", "pass"),
    ("switch key must match the epoch", L, " or ct.epoch != sk.from_epoch:", ":"),
    ("multiplier range", L, " or not 0 <= k < p.t:", ":"),
    ("switch adds noise to the bound", L, "added = p.n * p.digits * base_mask * ETA", "added = 0"),
    ("privacy proof is bound to the statement", B, 'zk.verify_knowledge(bytes.fromhex(d["public"]), statement_digest(statement), d["proof"])', 'zk.verify_knowledge(bytes.fromhex(d["public"]), b"", d["proof"])'),
    ("verifier insists on a tier", SP, 'if accept_tiers is not None and proof["tier"] not in tuple(accept_tiers):', "if False:"),
    ("verifier insists on a signature", SP, 'if require_signature is not None and sealed["preset"]["signature"] != require_signature:', "if False:"),
    ("reseal refuses unchanged keys", R, "if (bytes(new_key1), bytes(new_key2)) == (bytes(old_key1), bytes(old_key2)):", "if False:"),
    ("ratchet advances", R, "self.epoch += 1", "pass"),
]
if __name__ != "__main__":
    MUTATIONS = []                       # importing this file (test discovery) must not start the mutation run
survivors = []
for name, fname, old, new in MUTATIONS:
    tmp = pathlib.Path(tempfile.mkdtemp())
    shutil.copytree(REPO / "src" / "vega_superproof", tmp / "vega_superproof")
    f = tmp / "vega_superproof" / fname
    text = f.read_text(encoding="utf-8")
    if old not in text:
        print("CANNOT APPLY", name)
        survivors.append(name + " (could not apply)")
        continue
    f.write_text(text.replace(old, new, 1), encoding="utf-8")
    env = dict(os.environ)
    env["PYTHONPATH"] = str(tmp) + os.pathsep + env.get("PYTHONPATH", "")
    r = subprocess.run([sys.executable, "-W", "ignore", str(REPO / "tests" / "redteam_3_upper_tiers.py")], capture_output=True, text=True, env=env, timeout=900)
    print(("killed   " if r.returncode != 0 else "SURVIVED ") + name, flush=True)
    if r.returncode == 0:
        survivors.append(name)
    shutil.rmtree(tmp, ignore_errors=True)
print("survivors:", survivors or "none")
