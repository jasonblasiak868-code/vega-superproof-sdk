"""presets.py - configuration cards. A preset is data, and its hash is recorded in the audit commitment of every
seal, so anyone can later tell exactly which configuration produced a given proof."""
import hashlib
import json

PRESETS = {
    "standard": {"tier": 0, "layers": ["aes-256-gcm", "chacha20-poly1305"], "signature": "ed25519",
                 "note": "available everywhere; integrity/binding proof only"},
    "high_assurance": {"tier": 1, "layers": ["aes-256-gcm", "chacha20-poly1305"], "signature": "ed25519",
                       "note": "requires a registered SNARK prover; refuses otherwise"},
    "maximum": {"tier": 2, "layers": ["aes-256-gcm", "chacha20-poly1305"], "signature": "ml-dsa-65",
                "note": "requires a STARK prover and a post-quantum signer; refuses otherwise"},
    "private": {"tier": 1, "layers": ["aes-256-gcm", "chacha20-poly1305"], "signature": "ed25519",
                "note": "tier 1: a zero-knowledge proof of knowledge bound to the seal (builtin.enable_privacy); classical security"},
    "quantum_proof": {"tier": 2, "layers": ["aes-256-gcm", "chacha20-poly1305"], "signature": "hashsig-sha256-w16",
                      "note": "tier 2: only quantum-resistant primitives (builtin.enable_quantum_proof): 256-bit ciphers, SHA-256, a hash-based signature"},
    "locked_compute": {"tier": 3, "layers": ["aes-256-gcm", "chacha20-poly1305"], "signature": "hashsig-sha256-w16",
                       "note": "tier 3: quantum-proof seal bound to the epoch of the updating homomorphic encryption (builtin.enable_locked_compute)"},
    "post_quantum": {"tier": 0, "layers": ["aes-256-gcm", "chacha20-poly1305"], "signature": "ml-dsa-65",
                     "note": "tier 0 proof with a post-quantum signature; refuses without a signer"},
}


def preset_card(name: str) -> dict:
    if name not in PRESETS:
        raise KeyError(f"unknown preset {name!r}; known: {sorted(PRESETS)}")
    return {"name": name, **PRESETS[name]}


def preset_hash(card: dict) -> str:
    return hashlib.sha256(json.dumps(card, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()
