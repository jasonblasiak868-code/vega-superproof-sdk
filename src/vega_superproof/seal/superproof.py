"""superproof.py - the pipeline:

  capsule -> DAG -> AES-256-GCM (key 1) -> DAG -> ChaCha20-Poly1305 (key 2) -> DAG -> lineage root -> DAG
          -> proof (tier 0 / 1 / 2) -> DAG -> signed top root -> minted -> audit commitment

Rules enforced here:
  - every stage is written to the DAG BEFORE the next stage runs (dag.record_stage)
  - the tier is checked up front: an unavailable tier raises TierUnavailable and NOTHING is encrypted or recorded
  - only the signed top root and the proof go to the ledger (mint_top_root), never data, never keys
  - the tier and the preset card hash of every seal are recorded in an audit commitment (audit_commit)"""
import hashlib
import json
import os
import sys

from vega_custody.capsule import capsule as capsule_mod  # noqa: E402
from vega_superproof.seal import layers, presets, proof_tier0, proof_tier1, proof_tier2, proof_tier3, signature  # noqa: E402
from vega_superproof.seal.errors import SealError, TierUnavailable  # noqa: E402
from vega_superproof.seal.lineage import Lineage, key_id  # noqa: E402

_TIERS = {0: proof_tier0, 1: proof_tier1, 2: proof_tier2, 3: proof_tier3}


def _canon(o) -> bytes:
    return json.dumps(o, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _sha(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def mint_top_root(ledger, top_root: str, preset_hash: str, tier: int) -> dict:
    """Only the signed top root goes on chain. Metadata is the allow-listed commitment fields and nothing else."""
    commitment = {"kind": "SUPERPROOF_ROOT", "action": f"seal_tier{tier}", "action_hash": top_root,
                  "expiry": 0, "nonce_sha256": _sha(os.urandom(16))}
    return {"commitment": commitment, "receipt": ledger.mint(commitment)}


def audit_commit(dag, tier: int, preset_hash: str, top_root: str, receipt: dict, parents=None) -> dict:
    return dag.record("SEAL_AUDIT", {"tier": tier, "preset_hash": preset_hash, "top_root": top_root,
                                     "leaf": receipt["receipt"]["leaf"]}, parents=parents)


def seal(c: dict, key1: bytes, key2: bytes, signing_key, signing_public: bytes, dag, ledger,
         preset: str = "standard") -> dict:
    capsule_mod.verify(c)
    layers.validate_keys(key1, key2)                       # before ANY record is written
    card = presets.preset_card(preset)
    ph = presets.preset_hash(card)
    tier = card["tier"]
    # fail closed BEFORE any work: unavailable tier or signature algorithm refuses the whole seal
    if tier not in _TIERS:
        raise TierUnavailable(f"tier {tier} unknown")
    if tier > 0:
        _TIERS[tier].require_prover()
    if card["signature"] != "ed25519" and card["signature"] not in signature.supported():
        raise signature.SignatureUnavailable(f"{card['signature']} not registered")

    lin = Lineage()
    capsule_bytes = capsule_mod.to_bytes(c)
    aad = c["prefix_hash"].encode("ascii")

    s0 = dag.record_stage("capsule", _sha(capsule_bytes), preset_hash=ph)
    lin.add_content(_sha(capsule_bytes))
    lin.add_key_event(key_id(key1), "layer1")
    lin.add_key_event(key_id(key2), "layer2")

    env = layers.seal_layers(capsule_bytes, key1, key2, aad)
    s1 = dag.record_stage("layer1-aes-256-gcm", env["c1_sha256"], parents=[s0["entry_hash"]])
    lin.add_content(env["c1_sha256"])
    s2 = dag.record_stage("layer2-chacha20-poly1305", env["c2_sha256"], parents=[s1["entry_hash"]])
    lin.add_content(env["c2_sha256"])

    root = lin.root()
    s3 = dag.record_stage("lineage-root", root, parents=[s2["entry_hash"]])

    statement = {"capsule_sha256": _sha(capsule_bytes), "c1_sha256": env["c1_sha256"],
                 "c2_sha256": env["c2_sha256"], "lineage_root": root, "preset_hash": ph}
    proof = _TIERS[tier].prove(statement)
    s4 = dag.record_stage(f"proof-tier{tier}", _sha(_canon(proof)), parents=[s3["entry_hash"]])

    top_root = _sha(bytes.fromhex(proof["binding"]) + bytes.fromhex(root) + bytes.fromhex(ph))
    sig = signature.sign_root(signing_key, top_root, card["signature"], signing_public)
    minted = mint_top_root(ledger, top_root, ph, tier)
    audit = audit_commit(dag, tier, ph, top_root, minted, parents=[s4["entry_hash"]])
    return {"capsule_prefix_hash": c["prefix_hash"], "envelope": env, "proof": proof, "lineage_root": root, "top_root": top_root, "signature": sig,
            "preset": card, "preset_hash": ph, "minted": minted, "audit_entry": audit["entry_hash"]}


def verify_seal(sealed: dict, public: bytes, ledger, accept_tiers=None, require_signature: str = None) -> bool:
    """Independent re-check: proof binding, top root, signature, and that the root was really minted.
    accept_tiers / require_signature: what the VERIFIER insists on (a seal cannot vouch for its own strength), e.g. accept_tiers=(2, 3) for quantum-proof and
    require_signature='hashsig-sha256-w16'. A seal of any other tier or signature algorithm fails."""
    try:
        proof, ph = sealed["proof"], sealed["preset_hash"]
        if accept_tiers is not None and proof["tier"] not in tuple(accept_tiers):
            return False
        if require_signature is not None and sealed["preset"]["signature"] != require_signature:
            return False
        if presets.preset_hash(sealed["preset"]) != ph:
            return False
        if proof["tier"] == 0 and not proof_tier0.verify(proof, sealed["envelope"]["c2_sha256"]):
            return False
        if proof["tier"] > 0 and not _TIERS[proof["tier"]].verify(proof):
            return False
        card, env, st = sealed["preset"], sealed["envelope"], proof["statement"]
        if proof["tier"] != card["tier"]:
            return False                                   # a weaker proof than the configuration promised
        if not layers.ciphertext_digest_ok(env):
            return False                                   # the ciphertext present is not the one the digests describe
        if (st.get("c2_sha256"), st.get("c1_sha256"), st.get("lineage_root"), st.get("preset_hash")) != (env["c2_sha256"], env["c1_sha256"], sealed["lineage_root"], ph):
            return False                                   # the proof speaks about different material than this envelope (checked for EVERY tier)
        top = _sha(bytes.fromhex(proof["binding"]) + bytes.fromhex(sealed["lineage_root"]) + bytes.fromhex(ph))
        return (top == sealed["top_root"]
                and signature.verify_root(sealed["signature"], top, public, expected_alg=card["signature"])
                and ledger.verify(sealed["minted"]["commitment"]))
    except (KeyError, ValueError, TypeError, AttributeError, SealError):
        return False


def open_seal(sealed: dict, key1: bytes, key2: bytes) -> dict:
    """Decrypt and re-verify the capsule inside. Raises on a wrong key or any tampering."""
    raw = layers.open_layers(sealed["envelope"], key1, key2, sealed["capsule_prefix_hash"].encode("ascii"))
    c = capsule_mod.from_bytes(raw)
    if c["prefix_hash"] != sealed["capsule_prefix_hash"]:
        raise SealError("capsule inside does not match the sealed reference")
    return c
