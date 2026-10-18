"""proof_tier0.py - Tier 0: a hash-binding proof. It proves INTEGRITY and BINDING: this exact ciphertext, under this
exact configuration card and lineage, was produced by this pipeline. It is NOT zero-knowledge and it does not
prove a computation was done correctly; Tiers 1 and 2 exist for that and fail closed when unavailable."""
import hashlib
import json

TIER = 0


def _canon(o) -> bytes:
    return json.dumps(o, sort_keys=True, separators=(",", ":")).encode("utf-8")


def prove(statement: dict) -> dict:
    return {"tier": TIER, "statement": statement,
            "binding": hashlib.sha256(_canon({"tier": TIER, "statement": statement})).hexdigest()}


def verify(proof: dict, ciphertext_sha256: str = None) -> bool:
    if proof.get("tier") != TIER:
        return False
    if hashlib.sha256(_canon({"tier": TIER, "statement": proof["statement"]})).hexdigest() != proof.get("binding"):
        return False
    return ciphertext_sha256 is None or proof["statement"].get("c2_sha256") == ciphertext_sha256
