# vega-superproof-sdk — Specification
|
Spec v1.0 — 2026-10-19 — describes the published reference implementation as tested; where this document and the source disagree, the source wins.

## Table of Contents
- [1. Purpose and scope](#1-purpose-and-scope)
- [2. Tier architecture](#2-tier-architecture)
- [3. Zero-knowledge (zk.py) — privacy tier rationale](#3-zero-knowledge-zkpy--privacy-tier-rationale)
- [4. Fully homomorphic encryption (fhe.py) — fail-closed interface](#4-fully-homomorphic-encryption-fhepy--fail-closed-interface)
- [5. Updatable encryption (rotation.py)](#5-updatable-encryption-rotationpy)
- [6. Key re-wrap / scrambler (scrambler.py)](#6-key-re-wrap--scrambler-scramblerpy)
- [7. Vocabulary](#7-vocabulary)
- [8. Components](#8-components)
- [9. Guarantees and non-guarantees](#9-guarantees-and-non-guarantees)
- [10. Failure modes](#10-failure-modes)
- [11. Dependencies and layer rules](#11-dependencies-and-layer-rules)
- [12. Conformance](#12-conformance)

## 1. Purpose and scope

This specification covers the `vega_superproof` package (src layout) as published in this repository. It specifies:

- The two-layer seal pipeline (AES-256-GCM then ChaCha20-Poly1305) with algorithm tagging
- Dual lineage (content chain + key-event chain) bound into a single top root
- Four proof tiers (0–3) with fail-closed behavior when a tier is unavailable
- Configuration cards (presets) whose hash is recorded in every audit commitment
- The signature interface: built-in Ed25519, pluggable post-quantum algorithms (fail-closed), and the built-in hash-based stateful signature
- Selective disclosure via salted Merkle trees
- Additively homomorphic LWE with key rotation (epochs, switch keys, noise budget)
- Shamir secret splitting with checked reconstruction
- Key re-wrap (envelope encryption) gated by single-use human commitments
- Forward-secrecy key ratchet and `reseal()` linking old and new top roots
- Zero-knowledge proofs (zk.py) — classical security only
- Fully homomorphic encryption interface (fhe.py) — fail-closed until vetted backend registered

Out of scope: general-purpose SNARK/STARK provers, standardized post-quantum signatures (ML-DSA, SLH-DSA), fully homomorphic encryption implementations, any cryptographic expert review, production hardening, OS-level containment.

## 2. Tier architecture

The seal produces a proof at one of four tiers. Tier 0 is built-in and always available. Tiers 1–3 require a registered backend (via `builtin.enable_*()`); without one, the seal raises `TierUnavailable` **before any DAG write** — no silent downgrade, no partial output.

| Tier | Name | Status | What it proves | Backend registration |
|------|------|--------|----------------|---------------------|
| 0 | Integrity | **BUILT** (proof_tier0.py) | This exact ciphertext, configuration (preset), and lineage were produced. Binding = SHA-256(canonicalized {tier:0, statement}). Never faked. | None required (built-in) |
| 1 | Privacy (zero-knowledge) | **DESIGNED interface / BUILT backend** (proof_tier1.py + builtin.PrivacyBackend) | Schnorr proof of knowledge: the sealer knows the discrete log of a public point, bound to the seal statement via Fiat-Shamir. Classical security (secp256k1). | `builtin.enable_privacy(secret)` registers `PrivacyBackend` which uses `zk.prove_knowledge()` |
| 2 | Quantum-proof (hash-based) | **DESIGNED interface / BUILT backend** (proof_tier2.py + builtin.QuantumBackend) | Attestation that every primitive in the seal is quantum-resistant: layers ⊆ {aes-256-gcm, chacha20-poly1305}, hash = sha256, signature = hashsig-sha256-w16. Verifier re-checks against `QUANTUM_SAFE` allow-list. | `builtin.enable_quantum_proof()` registers `QuantumBackend` AND `hashsig.register()` |
| 3 | Locked compute | **DESIGNED interface / BUILT backend** (proof_tier3.py + builtin.ComputeBackend) | Tier 2 + binding to LWE parameter set ID, encryption epoch, and rotation log hash. Says *which generation* of the updating encryption the seal belongs to. | `builtin.enable_locked_compute(params_id, epoch, rotation_log_sha256)` registers `ComputeBackend` AND `hashsig.register()` |

**Fail-closed semantics (all tiers 1–3):** `proof_tierN.require_prover()` raises `TierUnavailable` if no backend registered. Registration is deliberate (`replace=True` required to change). The seal pipeline calls `require_prover()` **before any DAG write** (`superproof.seal()` lines 47–57).

**Design note:** "Quantum-proof" means the seal rests only on hashes and 256-bit symmetric keys — a large quantum computer weakens but does not break them (~128-bit security remains). The zero-knowledge tier (tier 1) relies on discrete log and is **NOT quantum-proof**. General-purpose SNARK/STARK provers are DESIGN ONLY — their interfaces fail closed.

## 3. Zero-knowledge (zk.py) — privacy tier rationale

### What the built zk.py does
`seal/zk.py` implements zero-knowledge proofs on secp256k1 (classical security, discrete log). It provides:

- **Pedersen commitments** (`commit`, `opens_to`): perfectly hiding, computationally binding (discrete log assumption).
- **Schnorr proof of knowledge** (`prove_knowledge`, `verify_knowledge`): proves knowledge of `x` for public `Y = x*G` bound to a message (signature of knowledge).
- **Bit-by-bit range proofs** (`prove_range`, `verify_range`): proves a committed value is in `[0, 2^bits)` without revealing it. Uses CDS OR-proofs per bit (each bit proven to be 0 or 1).
- **At-least proofs** (`prove_at_least`, `verify_at_least`): proves `v ≥ T` (and `< T + 2^bits`) via range proof on `C - T*G`.
- **Issuer attestation** (`attest`, `verify_attestation`): an issuer's Ed25519 signature over a commitment + label (e.g., "monthly_income_cents"), so a verifier knows WHO vouches for the hidden number.

Every proof is bound to a **CONTEXT** (bytes) through the Fiat-Shamir hash, so a proof made for one purpose does not verify for another.

**Honest limits:** Classical security only (a large quantum computer breaks the discrete log); the quantum-proof tier is hash-based (disclosure.py, hashsig.py). Plain Python, not constant-time, no independent cryptographic review: do not protect real secrets with it before one.

### Privacy-industry rationale (why this tier exists)
Tier 1 exists because **regulated industries cannot transfer sensitive data without proving the transfer happened without revealing the data itself**.

| Industry | What must stay private | What must be provable | How tier 1 addresses it |
|----------|------------------------|----------------------|-------------------------|
| **HIPAA / Medical** | Patient records, diagnoses, treatment codes, PHI | That a record was sealed, who authorized it, that the *same* record reaches the recipient | Schnorr proof of knowledge binds the sealer's secret to the seal statement — the verifier learns *that* the seal was produced by someone holding the authorizing key, without learning the record contents. Range proofs (`prove_range`) let a hospital prove "age ≥ 18" or "dosage ≤ max" without revealing the exact value. Issuer attestation lets a hospital sign a commitment to a diagnosis code. |
| **Banking / Finance** | Account numbers, transfer amounts, counterparties, balances | That a transfer was authorized, that amounts are within limits, that the same keys sealed both layers | At-least proofs (`prove_at_least`) let a bank prove "balance ≥ transfer amount" without revealing the balance. Range proofs prove "amount ≤ regulatory limit". The dual lineage binds the *content* (the transfer) to the *keys* (who authorized it) — a record cannot be re-attributed to different keys or different data. |
| **Government / Classified** | Classification levels, compartment markings, source identities | That a document was sealed at the correct classification, that the seal chain is unbroken, that rotation history is intact | The seal's dual lineage + tier 1 proof provides cryptographic evidence that the *same* keys produced both ciphertext layers and that the seal statement (including classification metadata) is bound to the proof. Rotation log hashes in tier 3 extend this to key rotation history. |

**What tier 1 does NOT do:** It does not make the data confidential (that is the two-layer encryption's job). It does not prove the *truth* of the committed values (that is the issuer's attestation). It does not provide quantum-proof privacy (tier 2/3 use hash-based primitives for that).

## 4. Fully homomorphic encryption (fhe.py) — fail-closed interface

`seal/fhe.py` provides **only the interface and the refusal**. The SDK carries no homemade FHE scheme.

```python
class FHEUnavailable(Exception):
    """Locked compute was requested and no FHE backend is registered."""

_BACKEND = None

def register_backend(backend, replace: bool = False): ...
def available() -> bool: ...
def locked_compute(operation: str, ciphertexts: list):  # raises FHEUnavailable if _BACKEND is None
```

**Behavior:** If no backend is registered, any request for locked compute raises `FHEUnavailable` — **it never falls back to computing on plaintext**. A backend must expose `evaluate(operation: str, ciphertexts: list) -> object`.

**Design note:** FHE hides the data; it does not prove the computation ran correctly. Pair it with an execution proof (see `vega-harness-sdk` cards/server_card.py: `verify_execution_proof`).

**Status:** DESIGN ONLY per STATUS.md. The interface exists to define the contract; a vetted backend (e.g., a wrapped OpenFHE or TFHE-rs library) must be registered deliberately before `locked_compute` becomes available.

## 5. Updatable encryption (rotation.py)

`seal/rotation.py` implements **updating encryption** for sealed records: change the keys without losing the seal's history.

- **`KeyRatchet(root_secret)`** — epoch keys that only move forward: `advance()` derives the next epoch's pair of layer keys and drops the old one, so a key stolen later cannot open what was sealed under an earlier epoch (forward secrecy). Python cannot truly wipe memory; the old key is released, not scrubbed: for a hard guarantee keep the ratchet in a hardware module.
- **`reseal(...)`** — opens a seal with the old keys and seals the same capsule under new keys (and, if asked, another preset), writing a `SEAL_ROTATED` record that links the old top root to the new one. The old seal stays valid as history; only the new one should be kept online.

The homomorphic layer rotates its own key (`lwe.KeyHolder.rotate`), also epoch by epoch.

**Invariants:** Keys differ per epoch and layer. New keys ≠ old keys. `SEAL_ROTATED` links roots. Old seal remains verifiable.

## 6. Key re-wrap / scrambler (scrambler.py)

**HONEST LABEL:** this is **KEY RE-WRAP (envelope encryption)**. The data key (DEK) is wrapped under a key-encryption key (KEK); rotation unwraps with the old KEK and wraps under the new one, **without touching the ciphertext**. It is not an updatable-encryption scheme over the ciphertext itself, and it is not homomorphic.

Two rules, both enforced here:
1. The card will not rotate without a **FRESH, minted, single-use commitment** (`require_commitment`).
2. Every rotation is committed to the chain and the **old key id is retired** (`commit_rotation`).

**Public interface:**
- `wrap(dek, kek, aad) -> bytes` — AES-GCM envelope encryption
- `unwrap(wrapped, kek, aad) -> bytes`
- `require_commitment(ledger, dag, commitment, action="rotate_keys") -> leaf` — checks: action matches, unexpired, minted in ledger, never used for rotation before (checks DAG for ROTATION entry with same commitment leaf)
- `commit_rotation(dag, old_kid, new_kid, commitment_leaf, parents) -> entry` — records rotation, retires old key id (ids only, never key material)
- `rotate(wrapped_dek, old_kek, new_kek, ledger, dag, commitment) -> dict` — sequences: require_commitment → unwrap → wrap → commit_rotation

## 7. Vocabulary

- **capsule**: the vega-custody unit of data + metadata (prefix_hash, payload, metadata) that enters the seal
- **seal**: the full pipeline output — envelope, proof, lineage root, top root, signature, preset, minted commitment, audit entry
- **envelope**: the two-layer ciphertext with nonces, algorithm tags, AAD hash, and ciphertext digests
- **lineage**: dual hash chain — content chain (what was sealed) and key-event chain (which keys sealed it)
- **top root**: SHA-256 of (proof binding || lineage root || preset hash); the single value that is signed and minted
- **preset**: a configuration card (tier, layers, signature algorithm, note) whose hash is recorded in the audit commitment
- **proof tier**: 0 = hash-binding integrity; 1 = privacy (Schnorr proof of knowledge); 2 = quantum-proof (attestation of quantum-resistant primitives); 3 = locked compute (tier 2 + homomorphic params/epoch/rotation log)
- **fail-closed**: a refusal that raises before any record is written; no silent downgrade, no partial output
- **DAG**: the append-only directed acyclic graph from vega-custody-sdk that records every stage
- **ledger**: the hash-chained ledger from vega-custody-sdk that mints commitments
- **commitment**: a single-use human-signed note (kind, action, action_hash, expiry, nonce_sha256) that gates actions
- **rotation**: key re-wrap + chain record that retires the old key id; requires a fresh minted commitment
- **reseal**: open a seal with old keys, re-seal with new keys, record SEAL_ROTATED linking old and new top roots

## 8. Components

### 8.1 seal/superproof.py — the pipeline

**Role**: Orchestrates the full seal: capsule → DAG → layer 1 → layer 2 → lineage root → proof (tier 0/1/2/3) → signed top root → mint → audit commitment.

**Public interface**:
- `seal(c, key1, key2, signing_key, signing_public, dag, ledger, preset="standard") -> dict`
- `verify_seal(sealed, public, ledger, accept_tiers=None, require_signature=None) -> bool`
- `open_seal(sealed, key1, key2) -> dict`
- `mint_top_root(ledger, top_root, preset_hash, tier) -> dict`
- `audit_commit(dag, tier, preset_hash, top_root, receipt, parents) -> dict`

**Behavior**: Validates keys and tier/signature availability BEFORE any DAG write. Records every stage to DAG in order. Only the signed top root and proof go to the ledger. On failure: raises `TierUnavailable`, `SignatureUnavailable`, `SealError`, `ValueError` — nothing is written.

**Invariants**: Every stage written to DAG before next stage runs. Tier checked up front; unavailable tier refuses the whole seal. Only signed top root reaches ledger. Tier and preset hash recorded in audit commitment.

### 8.2 seal/layers.py — two cipher layers

**Role**: AES-256-GCM (key1) then ChaCha20-Poly1305 (key2) with algorithm tags, nonces, AAD, and ciphertext digests.

**Public interface**:
- `generate_key() -> bytes`
- `validate_keys(key1, key2) -> None`
- `seal_layers(plaintext, key1, key2, aad) -> dict`
- `ciphertext_digest_ok(env) -> bool`
- `open_layers(env, key1, key2, aad) -> bytes`

**Behavior**: Authenticated encryption; any tampering rejected on open. Algorithm tags prevent guessing. Keys validated before any record write. On failure: `ValueError` (malformed envelope, weak keys) or `InvalidTag` (wrong key/tampering).

**Invariants**: Keys must be 32 random bytes, distinct. Nonces 12 bytes. Ciphertext digest in envelope matches actual ciphertext.

### 8.3 seal/presets.py — configuration cards

**Role**: Data-only configuration cards; hash recorded in every audit commitment.

**Public interface**:
- `preset_card(name) -> dict`
- `preset_hash(card) -> str`
- `PRESETS` dict: "standard" (tier 0, ed25519), "high_assurance" (tier 1, ed25519), "maximum" (tier 2, ml-dsa-65), "private" (tier 1, ed25519), "quantum_proof" (tier 2, hashsig-sha256-w16), "locked_compute" (tier 3, hashsig-sha256-w16), "post_quantum" (tier 0, ml-dsa-65)

**Behavior**: `preset_card` raises `KeyError` for unknown names. Hash is deterministic JSON canonicalization.

**Invariants**: Preset hash uniquely identifies the configuration. Same card → same hash.

### 8.4 seal/proof_tier0.py — integrity proof

**Role**: Hash-binding proof (always available). Proves this exact ciphertext, configuration, and lineage were produced.

**Public interface**:
- `prove(statement) -> dict` with tier=0, statement, binding hash
- `verify(proof, ciphertext_sha256=None) -> bool`

**Behavior**: Binding = SHA-256 of canonicalized {tier, statement}. Verification checks binding and optional ciphertext match.

**Invariants**: Never fakes a proof. Never silently downgrades. Tier 0 is always available.

### 8.5 seal/proof_tier1.py — privacy tier (zero-knowledge interface)

**Role**: Interface for zero-knowledge proof of knowledge. Fails closed without registered prover.

**Public interface**:
- `register(backend, replace=False)`
- `available() -> bool`
- `require_prover() -> None` (raises `TierUnavailable`)
- `prove(statement) -> dict` with tier=1, statement, proof_hex, binding
- `verify(proof) -> bool`

**Behavior**: `require_prover()` raises `TierUnavailable` if no backend registered. Backend must expose `prove(statement)->bytes` and `verify(statement, proof)->bool`.

**Invariants**: No silent fallback. Registration is deliberate (replace=True required to change).

### 8.6 seal/proof_tier2.py — quantum-proof tier (hash-based interface)

**Role**: Interface for quantum-resistant proof. Fails closed without registered prover.

**Public interface**: Same as tier 1 (TIER=2).

**Behavior**: Same fail-closed semantics as tier 1.

**Invariants**: Same as tier 1.

### 8.7 seal/proof_tier3.py — locked compute tier

**Role**: Interface for locked compute proof (tier 2 + homomorphic params/epoch/rotation log). Fails closed without registered prover.

**Public interface**: Same as tier 1 (TIER=3).

**Behavior**: Same fail-closed semantics.

**Invariants**: Same as tier 1.

### 8.8 seal/signature.py — algorithm-tagged signatures

**Role**: Sign/verify the top root. Ed25519 built in; post-quantum algorithms are pluggable interfaces that fail closed.

**Public interface**:
- `register(alg, backend, replace=False)`
- `supported() -> list[str]`
- `new_ed25519() -> (private, public_bytes)`
- `sign_root(private, root_hex, alg="ed25519", public=None) -> dict`
- `verify_root(sig, root_hex, public, expected_alg=None) -> bool`

**Behavior**: `expected_alg` (from configuration) must match signature's `alg` field — prevents algorithm confusion. Unregistered algorithm raises `SignatureUnavailable`.

**Invariants**: Algorithm comes from configuration, not the signature object. Registration is deliberate.

### 8.9 seal/hashsig.py — hash-based stateful signature

**Role**: Winternitz one-time keys (w=16) under Merkle tree, SHA-256 only. Quantum-proof (rests on hash only).

**Public interface**:
- `Signer(height=6, seed=None, state_path=None, pub_seed=None)` with `.public`, `.sign(msg)`, `.remaining`
- `verify(public, msg, sig, height=None) -> bool`
- `HashSigBackend` (plugs into `signature.register()`)
- `register(replace=False)`

**Behavior**: Stateful — index written to disk BEFORE signature returned. Refuses to go backwards. Refuses when keys exhausted. State file must never be copied/restored.

**Invariants**: Each one-time key used exactly once. Index persisted before signature. Height 1–10.

### 8.10 seal/disclosure.py — selective disclosure

**Role**: Commit to a record, later reveal chosen fields. Salted Merkle tree, padded to power of two, leaves shuffled by secret permutation.

**Public interface**:
- `commit_record(fields) -> (root_hex, openings)`
- `disclose(openings, names) -> proof`
- `verify_disclosure(root_hex, proof) -> dict[name]=value or None`

**Behavior**: Root hides values, names, and exact field count (size bucket only). Verification returns shown fields or `None` on any failure.

**Invariants**: Only SHA-256. Max 1024 fields. Field names short non-empty text.

### 8.11 seal/lwe.py — additively homomorphic LWE with rotation

**Role**: Encrypt integers; anyone can add, subtract, scale by plaintext, compute dot products on ciphertexts. Key rotation via switch keys, epochs, noise budget.

**Public interface**:
- `Params(n=512, q_bits=48, t_bits=16, base_bits=8)` with `.id`, `.limit`, `.insecure`
- `KeyHolder(params, epoch)` with `.encrypt(m)`, `.decrypt(ct)`, `.rotate() -> (new_holder, SwitchKey)`, `.destroy()`
- `Ciphertext` with `.to_dict()`, `.from_dict()`
- `SwitchKey`
- `add(p, x, y)`, `sub(p, x, y)`, `scale(p, x, k)`, `total(p, cts)`, `dot(p, cts, weights)`, `switch(p, ct, sk)`
- `LweBackend` (plugs into `fhe.register_backend()`)

**Behavior**: Additive only — no ciphertext×ciphertext, no encrypted comparisons. Noise budget enforced — operations that would exceed limit raise `NoiseBudgetExhausted`. Epochs and parameter sets never mix. Old key wiped on rotation.

**Invariants**: Decryption correct while noise < delta/2. Switch key reveals nothing about secrets. `insecure` flag true for n<256.

### 8.12 seal/fhe.py — fully homomorphic interface (fail-closed)

**Role**: Interface for **full FHE**. The SDK carries the interface and the refusal, not a homemade FHE scheme. Fails closed without registered backend.

**Public interface**:
- `register_backend(backend, replace=False)` — backend must expose `evaluate(operation: str, ciphertexts: list) -> object`
- `available() -> bool`
- `locked_compute(operation: str, ciphertexts: list)` — raises `FHEUnavailable` if no backend registered

**Behavior**: Raises `FHEUnavailable` if no backend. **It never falls back to computing on plaintext.** A backend must expose `evaluate(operation: str, ciphertexts: list) -> object`.

**Design note**: FHE hides the data; it does not prove the computation ran correctly. Pair it with an execution proof (see `vega-harness-sdk` cards/server_card.py: `verify_execution_proof`).

**Status**: DESIGN ONLY per STATUS.md. The interface exists to define the contract; a vetted backend (e.g., a wrapped OpenFHE or TFHE-rs library) must be registered deliberately before `locked_compute` becomes available.

### 8.13 seal/keysplit.py — Shamir secret sharing

**Role**: Split secret across roles (TPM, card, human). GF(256) Shamir, k-of-n.

**Public interface**:
- `split(secret, k, n) -> list[(x, bytes)]`
- `combine(shares) -> bytes` (warns: returns something even if wrong)
- `split_checked(secret, k, n) -> (shares, check_hash)`
- `combine_checked(shares, check, k, n) -> bytes` (verifies)
- `split_roles(secret, k=2) -> dict[role]=(x, bytes)` for roles=("tpm","card","human")

**Behavior**: `combine_checked` raises `ValueError` on too few, wrong, or corrupt shares. Check hash is SHA-256 of secret — safe for random keys, NOT for guessable secrets.

**Invariants**: Threshold k≥2, n≤255. Shares have distinct x in 1..255.

### 8.14 seal/scrambler.py — key re-wrap gated by commitment

**Role**: **KEY RE-WRAP (envelope encryption)** — the data key (DEK) is wrapped under a key-encryption key (KEK); rotation unwraps with the old KEK and wraps under the new one, **without touching the ciphertext**. It is not an updatable-encryption scheme over the ciphertext itself, and it is not homomorphic.

Two rules, both enforced here:
1. The card will not rotate without a **FRESH, minted, single-use commitment** (`require_commitment`).
2. Every rotation is committed to the chain and the **old key id is retired** (`commit_rotation`).

**Public interface**:
- `wrap(dek, kek, aad) -> bytes` — AES-GCM envelope encryption
- `unwrap(wrapped, kek, aad) -> bytes`
- `require_commitment(ledger, dag, commitment, action="rotate_keys") -> leaf` — checks: action matches, unexpired, minted in ledger, never used for rotation before (checks DAG for ROTATION entry with same commitment leaf)
- `commit_rotation(dag, old_kid, new_kid, commitment_leaf, parents) -> entry` — records rotation, retires old key id (ids only, never key material)
- `rotate(wrapped_dek, old_kek, new_kek, ledger, dag, commitment) -> dict` — sequences: require_commitment → unwrap → wrap → commit_rotation

**Behavior**: Commitment must be for "rotate_keys", unexpired, minted, never used for rotation before. Old key id retired; cannot be used again. Keys never appear in records — only key ids.

**Invariants**: Single-use commitment. Old key id retired permanently. Rotation recorded before new wrap returned.

### 8.15 seal/rotation.py — updating encryption for sealed records

**Role**: **UPDATING ENCRYPTION** for sealed records: change the keys without losing the seal's history.

- **`KeyRatchet(root_secret)`** — epoch keys that only move forward: `advance()` derives the next epoch's pair of layer keys and drops the old one, so a key stolen later cannot open what was sealed under an earlier epoch (forward secrecy). Python cannot truly wipe memory; the old key is released, not scrubbed: for a hard guarantee keep the ratchet in a hardware module.
- **`reseal(...)`** — opens a seal with the old keys and seals the same capsule under new keys (and, if asked, another preset), writing a `SEAL_ROTATED` record that links the old top root to the new one. The old seal stays valid as history; only the new one should be kept online.

The homomorphic layer rotates its own key (`lwe.KeyHolder.rotate`), also epoch by epoch.

**Public interface**:
- `KeyRatchet(root_secret)` with `.current() -> (key1, key2)`, `.advance() -> epoch`
- `reseal(sealed, old_key1, old_key2, new_key1, new_key2, signing_key, signing_public, dag, ledger, preset=None) -> new_sealed`

**Behavior**: Ratchet derives next epoch keys via HMAC-SHA256; old key released (not scrubbed — Python cannot truly wipe). `reseal` opens old seal, seals same capsule under new keys, records `SEAL_ROTATED` linking old and new top roots. Old seal stays valid as history.

**Invariants**: Keys differ per epoch and layer. New keys ≠ old keys. `SEAL_ROTATED` links roots. Old seal remains verifiable.

### 8.16 seal/zk.py — zero-knowledge proofs (classical security)

**Role**: Pedersen commitments, Schnorr proof of knowledge, bit-by-bit range proofs, at-least proofs, issuer attestation. **Classical security only** (secp256k1 discrete log). The quantum-proof tier uses hash-based primitives (disclosure.py, hashsig.py).

**Public interface**:
- `commit(value, blinding=None) -> (commitment_bytes, blinding)` — Pedersen commitment `C = v*G + r*H`: hides `v` (perfectly) and binds to it (as hard as the discrete log). Keep the blinding secret; it opens the commitment.
- `opens_to(commitment, value, blinding) -> bool`
- `public_of(x) -> bytes` — `Y = x*G`
- `prove_knowledge(x, message) -> proof`, `verify_knowledge(public, message, proof) -> bool` — Schnorr proof that the prover knows `x` for public `Y = x*G`, bound to a message (signature of knowledge).
- `prove_range(value, blinding, bits, context) -> proof`, `verify_range(commitment, bits, proof, context) -> bool` — proves a committed value is in `[0, 2^bits)` without revealing it. Bit-by-bit commitments, each proved to hold 0 or 1 by a CDS OR-proof. Max 64 bits.
- `prove_at_least(value, blinding, threshold, bits, context) -> proof`, `verify_at_least(commitment, threshold, bits, proof, context) -> bool` — proves `v ≥ T` (and `< T + 2^bits`) via range proof on `C - T*G`. The 'income at least X' / 'balance at least X' building block.
- `attest(issuer_private, commitment, label) -> sig_hex`, `verify_attestation(issuer_public, commitment, label, sig_hex) -> bool` — an issuer's Ed25519 signature over a commitment + label (e.g., "monthly_income_cents"), so a verifier knows WHO vouches for the hidden number.

Every proof is bound to a **CONTEXT** (bytes) through the Fiat-Shamir hash, so a proof made for one purpose does not verify for another.

**Behavior**: Classical security only (discrete log). Plain Python, not constant-time. Proofs bound to context via Fiat-Shamir. At-least proves v ≥ T via range proof on C - T*G.

**Invariants**: Value in range for range proof. Context bound into challenge. No proof exists for value outside range.

**Honest limits**: A large quantum computer breaks the discrete log; the quantum-proof tier is hash-based (disclosure.py, hashsig.py). Plain Python, not constant-time, no independent cryptographic review: do not protect real secrets with it before one.

### 8.17 seal/ec.py — secp256k1 arithmetic

**Role**: Group operations for zk.py. Plain Python, checked constants on import.

**Public interface**:
- `on_curve(pt) -> bool`
- `add(a, b)`, `neg(a)`, `mul(k, pt)`
- `encode(pt) -> bytes` (33-byte compressed), `decode(bytes) -> pt`
- `hash_to_scalar(*parts) -> int`, `hash_to_point(seed) -> pt`
- Constants: `P`, `N`, `G`, `H`, `INF`

**Behavior**: Self-check on import (G on curve, N*G=INF). Not constant-time.

### 8.18 seal/lineage.py — dual lineage

**Role**: Content chain + key-event chain bound into single root.

**Public interface**:
- `key_id(key) -> str` (SHA-256 with domain separation)
- `Lineage` with `.add_content(digest)`, `.add_key_event(kid, event)`, `.root() -> str`

**Behavior**: Content chain hashes each ciphertext digest. Key chain hashes "event:key_id". Root = SHA-256(content_head || key_head).

**Invariants**: Key id is NOT plain hash of key (domain-separated). Dual lineage prevents re-attribution.

### 8.19 seal/builtin.py — three working backends

**Role**: Concrete backends for tiers 1–3, enabled deliberately at startup.

**Public interface**:
- `PrivacyBackend(secret)` — Schnorr proof of knowledge of secret, bound to seal statement
- `QuantumBackend()` — attests that seal uses only quantum-safe primitives (QUANTUM_SAFE set)
- `ComputeBackend(params_id, epoch, rotation_log_sha256)` — QuantumBackend + binds to HE params, epoch, rotation log
- `enable_privacy(secret, replace=False) -> PrivacyBackend`
- `enable_quantum_proof(replace=False) -> QuantumBackend`
- `enable_locked_compute(params_id, epoch, rotation_log_sha256, replace=False) -> ComputeBackend`

**Behavior**: NOT registered automatically. Tier still fails closed until `enable_*()` called. `QuantumBackend` verifies layers ⊆ {aes-256-gcm, chacha20-poly1305}, hash=sha256, signature=hashsig-sha256-w16.

### 8.20 seal/errors.py — fail-closed exceptions

**Role**: Shared exceptions.

**Public interface**:
- `SealError`, `TierUnavailable(SealError)`, `SignatureUnavailable(SealError)`

## 9. Guarantees and non-guarantees

### Guarantees

| Guarantee | Module | Test |
|---|---|---|
| Two-layer AEAD encryption with algorithm tags | layers | test_seal.py:48-58 |
| Dual lineage binds content and keys | lineage | test_seal.py:63-76 |
| Tier 0 proof always available, never faked | proof_tier0 | test_seal.py:61-71 |
| Tier 1–3 fail closed without registered prover | proof_tier1/2/3 | test_seal.py:79-84 |
| Post-quantum signature algorithms fail closed | signature | test_seal.py:84 |
| Hash-based signature is stateful, index persisted before sign | hashsig | redteam_3_upper_tiers.py:200-227 |
| Selective disclosure hides values/names/count | disclosure | redteam_3_upper_tiers.py:267-299 |
| LWE additive ops + rotation + noise budget enforced | lwe | redteam_3_upper_tiers.py:304-415 |
| Shamir split + checked reconstruction | keysplit | redteam_2_keys_backends_rotation.py:19-58 |
| Key re-wrap gated by single-use commitment | scrambler | test_seal.py:99-116 |
| Key ratchet forward secrecy + reseal links roots | rotation | redteam_3_upper_tiers.py:493-529 |
| Configuration hash recorded in audit commitment | presets | test_seal.py:134-137 |
| No plaintext or keys reach DAG/ledger | superproof | test_seal.py:70-72 |
| Verifier can insist on minimum tier and signature alg | superproof.verify_seal | redteam_3_upper_tiers.py:434-463 |

### Non-guarantees

| Non-guarantee | Reason |
|---|---|
| No independent cryptographic review | Plain Python, not constant-time |
| Not constant-time — side channels possible | Written for clarity, not production |
| LWE is additive only — not fully homomorphic | No ciphertext×ciphertext, no comparisons |
| Tier 1 (zk) relies on discrete log — not quantum-proof | Classical security only |
| Hash signature state file must never be copied | Reuse of one-time key enables forgery |
| SNARK/STARK, ML-DSA/SLH-DSA, full FHE are DESIGN ONLY | Interfaces fail closed (STATUS.md) |
| Not an OS sandbox or containment system | Process-level only |
| Not legal advice; licence draft not attorney-reviewed | Policy only |

## 10. Failure modes

| Failure | Behavior | Test |
|---|---|---|
| Tampered ciphertext | `open_layers` raises `InvalidTag`/`ValueError`; `verify_seal` returns `False` | test_seal.py:52-56, redteam_1:37-41 |
| Wrong key | `InvalidTag` on open; `verify_seal` returns `False` | test_seal.py:50-51 |
| Altered top root / lineage root / preset hash | `verify_seal` returns `False` | redteam_1:49-53 |
| Weaker proof than preset promised | `verify_seal` returns `False` (tier mismatch) | redteam_1:55-61 |
| Algorithm confusion (signature alg from doc not config) | `verify_seal` returns `False` (expected_alg check) | redteam_1:63-77 |
| Foreign ledger / wrong public key | `verify_seal` returns `False` | redteam_1:79-83 |
| Malformed seal/envelope | `verify_seal` returns `False`; `open_layers` raises `ValueError` | redteam_1:85-103 |
| Unavailable tier/signature | `seal` raises `TierUnavailable`/`SignatureUnavailable` before any write | test_seal.py:79-84 |
| Rotation with unminted/expired/wrong-action/used commitment | `scrambler.rotate` raises `RotationRefused` | test_seal.py:105-120 |
| LWE noise budget exhausted | Operations raise `NoiseBudgetExhausted` | redteam_3_upper_tiers.py:358-365 |
| LWE epoch/params mismatch | `LweError` raised | redteam_3_upper_tiers.py:345-356 |
| Too few/wrong shares for Shamir | `combine_checked` raises `ValueError` | redteam_2:31-41 |
| Hashsig index exhausted / state file tampered | `HashSigError` raised | redteam_3:200-227 |

## 11. Dependencies and layer rules

Registry entry (verbatim from ORGANISM_MAP.md):
```
vega-superproof-sdk | 2 seal | custody
```

Dependencies point down layers only, never up or sideways. This kit depends on `vega-custody-sdk` (layer 0) for capsules, DAG, ledger. It does not depend on layers 1, 3–15.

## 12. Conformance

A third party can verify by running the test suite:

```bash
PYTHONPATH=src:../vega-custody-sdk/src python3 tests/test_seal.py
PYTHONPATH=src:../vega-custody-sdk/src python3 tests/redteam_1_seal_verification.py
PYTHONPATH=src:../vega-custody-sdk/src python3 tests/redteam_2_keys_backends_rotation.py
PYTHONPATH=src:../vega-custody-sdk/src python3 tests/redteam_3_upper_tiers.py
```

Passing means: all 102 tests pass (STATUS.md), the fail-closed behaviors hold, the cryptographic primitives execute as specified, and the DAG/ledger records match the documented stages.

Passing does NOT mean: cryptographically expert-reviewed, constant-time, side-channel resistant, production-hardened, or that the DESIGN ONLY tiers (SNARK/STARK, ML-DSA/SLH-DSA, full FHE) are implemented — their interfaces remain fail-closed.