# vega-superproof-sdk — Architecture

## Table of Contents
- [1. The organism (family picture)](#1-the-organism-family-picture)
- [2. Tier architecture](#2-tier-architecture)
- [3. Internal drawing — modules and flows](#3-internal-drawing--modules-and-flows)
- [4. Mermaid diagram](#4-mermaid-diagram)
- [5. Sequence — main scenario: seal a capsule at tier 2 (quantum-proof)](#5-sequence--main-scenario-seal-a-capsule-at-tier-2-quantum-proof)
- [6. Zero-knowledge (zk.py) — privacy tier internals](#6-zero-knowledge-zkpy--privacy-tier-internals)
- [7. Fully homomorphic encryption (fhe.py) — fail-closed interface](#7-fully-homomorphic-encryption-fhepy--fail-closed-interface)
- [8. Updatable encryption (rotation.py)](#8-updatable-encryption-rotationpy)
- [9. Key re-wrap / scrambler (scrambler.py)](#9-key-re-wrap--scrambler-scramblerpy)
- [10. Trust boundaries](#10-trust-boundaries)

## 1. The organism (family picture)

```
                 ┌──────────────────────────┐
                 │   THE HUMAN (the owner)  │
                 └────────────┬─────────────┘
                              v single-use signed commitments
 15 assemble   vega-umbrella-sdk
 14 deliberate vega-council-sdk  vega-galaxy-sdk
 13 watch      vega-governance-feed-sdk
 12 verify     vega-metacog-sdk
 11 reason     vega-reasoning-sdk
 10 observe    vega-trace-sdk
  9 interface  vega-terminal-sdk
  8 learn      vega-train-sdk
  7 knowledge  vega-dkg-lattice-sdk
  6 conduct    vega-harness-sdk
  5 memory     vega-librarian-sdk
  4 contain    vega-two-gate-sdk
  3 adapt      vega-pareah-sdk
>>> 2 seal       vega-superproof-sdk <<<   layered sealing and proof tiers
  1 authority  vega-governance-jacket-sdk
  0 record     vega-custody-sdk            capsules, DAG, hash-chained ledger
```

**Below (layer 0)**: `vega-custody-sdk` provides capsules (the data unit), the append-only DAG (every stage recorded in order), and the hash-chained ledger (mints commitments). Superproof consumes these — it does not reimplement them.

**Above (layers 3+)**: `vega-pareah-sdk` (adapters), `vega-two-gate-sdk` (containment), `vega-harness-sdk` (conduct), and higher layers consume superproof's sealed envelopes, audit entries, and verification results. They rely on the top root, proof tier, and preset hash to know what was sealed and at what assurance level.

## 2. Tier architecture

The seal produces a proof at one of four tiers. Tier 0 is built-in and always available. Tiers 1–3 require a registered backend (via `builtin.enable_*()`); without one, the seal raises `TierUnavailable` **before any DAG write** — no silent downgrade, no partial output.

| Tier | Name | Status | What it proves | Backend registration |
|------|------|--------|----------------|---------------------|
| 0 | Integrity | **BUILT** (`proof_tier0.py`) | This exact ciphertext, configuration (preset), and lineage were produced. Binding = SHA-256(canonicalized {tier:0, statement}). Never faked. | None required (built-in) |
| 1 | Privacy (SNARK) | **DESIGNED interface / BUILT backend** (`proof_tier1.py` + `builtin.PrivacyBackend`) | Schnorr proof of knowledge: the sealer knows the discrete log of a public point, bound to the seal statement via Fiat-Shamir. Classical security (secp256k1). | `builtin.enable_privacy(secret)` registers `PrivacyBackend` which uses `zk.prove_knowledge()` |
| 2 | Quantum-proof (STARK) | **DESIGNED interface / BUILT backend** (`proof_tier2.py` + `builtin.QuantumBackend`) | Attestation that every primitive in the seal is quantum-resistant: layers ⊆ {aes-256-gcm, chacha20-poly1305}, hash = sha256, signature = hashsig-sha256-w16. Verifier re-checks against `QUANTUM_SAFE` allow-list. | `builtin.enable_quantum_proof()` registers `QuantumBackend` AND `hashsig.register()` |
| 3 | Locked compute | **DESIGNED interface / BUILT backend** (`proof_tier3.py` + `builtin.ComputeBackend`) | Tier 2 + binding to LWE parameter set ID, encryption epoch, and rotation log hash. Says *which generation* of the updating encryption the seal belongs to. | `builtin.enable_locked_compute(params_id, epoch, rotation_log_sha256)` registers `ComputeBackend` AND `hashsig.register()` |

**Fail-closed semantics (all tiers 1–3):** `proof_tierN.require_prover()` raises `TierUnavailable` if no backend registered. Registration is deliberate (`replace=True` required to change). The seal pipeline calls `require_prover()` **before any DAG write** (`superproof.seal()` lines 47–57).

**Design note:** "Quantum-proof" means the seal rests only on hashes and 256-bit symmetric keys — a large quantum computer weakens but does not break them (~128-bit security remains). The zero-knowledge tier (tier 1) relies on discrete log and is **NOT quantum-proof**. General-purpose SNARK/STARK provers are DESIGN ONLY — their interfaces fail closed.

## 3. Internal drawing — modules and flows

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                              SUPERPROOF PIPELINE                            │
└─────────────────────────────────────────────────────────────────────────────┘

  CAPSULE (vega-custody)                                                      │
       │                                                                       │
       ▼                                                                       │
  ┌─────────┐    validate_keys()    ┌──────────────────────────────────┐     │
  │ PRESETS │──────────────────────▶│  seal/layers.py                  │     │
  │ preset_card()                     │  seal_layers()                   │     │
  │ preset_hash()                     │  - AES-256-GCM (key1)            │     │
  └─────────┘                         │  - ChaCha20-Poly1305 (key2)      │     │
       │                              │  - algorithm tags, nonces, AAD   │     │
       │ preset                       │  - c1_sha256, c2_sha256 digests  │     │
       ▼                              └──────────────┬───────────────────┘     │
  ┌───────────────────────────────────┐             │                         │
  │ seal/superproof.py                │             ▼                         │
  │ seal()                            │    ┌────────────────────────┐        │
  │ 1. validate keys, tier, sig       │    │ seal/lineage.py        │        │
  │ 2. fail closed if unavailable     │    │ Lineage                │        │
  │ 3. record STAGE:capsule to DAG    │    │ - content chain        │◀───────┘
  │ 4. seal_layers() → envelope       │    │ - key-event chain      │
  │ 5. record STAGE:layer1, layer2    │    │ - root() = H(content||key)│
  │ 6. lineage.root()                 │    └───────────┬────────────┘
  │ 7. record STAGE:lineage-root      │                │
  │ 8. _TIERS[tier].prove()           │                ▼
  │ 9. record STAGE:proof-tier{N}     │    ┌────────────────────────┐
  │ 10. top_root = H(binding||root)   │    │ PROOF TIERS            │
  │ 11. signature.sign_root()         │    │ proof_tier0.py (TIER=0)│
  │ 12. mint_top_root() → ledger      │    │ proof_tier1.py (TIER=1)│
  │ 13. audit_commit() → DAG          │    │ proof_tier2.py (TIER=2)│
  └───────────────────────────────────┘    │ proof_tier3.py (TIER=3)│
                                            │ builtin.py (backends)  │
                                            └────────────────────────┘
                                              ▲              ▲
                                              │              │
                                              │    ┌─────────┴─────────┐
                                              │    │ seal/signature.py │
                                              │    │ - register()      │
                                              │    │ - sign_root()     │
                                              │    │ - verify_root()   │
                                              │    │ - Ed25519 builtin │
                                              │    └────────┬──────────┘
                                              │             │
                                              │    ┌────────┴──────────┐
                                              │    │ seal/hashsig.py   │
                                              │    │ Signer (stateful) │
                                              │    │ - Winternitz w=16 │
                                              │    │ - Merkle, SHA-256 │
                                              │    │ - index on disk   │
                                              │    └───────────────────┘
                                              │
                                     ┌────────┴────────┐
                                     │  VERIFICATION   │
                                     │ verify_seal()   │
                                     │ - proof binding │
                                     │ - top root      │
                                     │ - signature     │
                                     │ - ledger mint   │
                                     │ - accept_tiers  │
                                     │ - require_sign  │
                                     └─────────────────┘

AUTHORITY FLOW (down from human, never from model):
human signs commitment → jacket gates check it → contained execution →
seal writes every stage to DAG → top root signed → minted to ledger →
audit commitment records tier + preset hash

DATA/KNOWLEDGE FLOW (up from record):
custody records → superproof audit entries (tier, preset, top_root) →
librarian distills lessons → dkg-lattice builds knowledge graph →
reasoning/galaxy forecasts → harness pre-registers paths → metacog gates →
feed/galaxy shows human → human decides again
```

## 3. Mermaid diagram

```mermaid
graph TD
    A[Capsule] --> B{Presets}
    B --> C[Validate Keys, Tier, Sig]
    C -->|fail| D[TierUnavailable/SignatureUnavailable]
    C -->|ok| E[DAG: STAGE:capsule]
    E --> F[layers.seal_layers]
    F --> G[DAG: STAGE:layer1, layer2]
    G --> H[Lineage.root]
    H --> I[DAG: STAGE:lineage-root]
    I --> J{Proof Tier}
    J -->|0| K[proof_tier0.prove]
    J -->|1| L[proof_tier1.prove]
    J -->|2| M[proof_tier2.prove]
    J -->|3| N[proof_tier3.prove]
    K --> O[DAG: STAGE:proof-tier0]
    L --> O
    M --> O
    N --> O
    O --> P[top_root = H(binding||root||preset_hash)]
    P --> Q[signature.sign_root]
    Q --> R[mint_top_root -> Ledger]
    R --> S[audit_commit -> DAG]
    S --> T[Sealed Envelope]
    T --> U[verify_seal]
    U --> V{Proof Binding}
    U --> W{Top Root}
    U --> X{Signature}
    U --> Y{Ledger Mint}
    U --> Z{accept_tiers / require_signature}
```

## 4. Sequence — main scenario: seal a capsule at tier 2 (quantum-proof)

```
HUMAN                          SUPERPROOF                          CUSTODY (DAG/LEDGER)
  │                                 │                                     │
  │ signs commitment                │                                     │
  │────────────────────────────────▶│                                     │
  │                                 │                                     │
  │                    seal(c, k1, k2, sk, pub, dag, led, "quantum_proof")
  │                                 │                                     │
  │                    ┌─────────────────────────────────┐                │
  │                    │ 1. validate keys, tier=2, hashsig │                │
  │                    │ 2. builtin.enable_quantum_proof() │                │
  │                    │    must be called already         │                │
  │                    └─────────────────────────────────┘                │
  │                                 │                                     │
  │                    record STAGE:capsule                             │────▶
  │                                 │                                     │
  │                    seal_layers (AES-256-GCM, ChaCha20)              │
  │                                 │                                     │
  │                    record STAGE:layer1, STAGE:layer2                │────▶
  │                                 │                                     │
  │                    Lineage.root()                                    │
  │                                 │                                     │
  │                    record STAGE:lineage-root                        │────▶
  │                                 │                                     │
  │                    proof_tier2.prove(statement)                     │
  │                    (QuantumBackend attests                          │
  │                     primitives are quantum-safe)                   │
  │                                 │                                     │
  │                    record STAGE:proof-tier2                         │────▶
  │                                 │                                     │
  │                    top_root = H(binding || root || preset_hash)     │
  │                                 │                                     │
  │                    sign_root(hashsig.Signer, top_root)             │
  │                                 │                                     │
  │                    mint_top_root()                                  │────▶
  │                                 │                                     │
  │                    audit_commit(tier=2, preset_hash, top_root)     │────▶
  │                                 │                                     │
  │                    return sealed dict                               │
  │◀────────────────────────────────│                                     │
  │                                 │                                     │
```

## 5. Trust boundaries

| Boundary | What crosses | Enforced by |
|---|---|---|
| Human → Seal pipeline | Single-use signed commitment (action, expiry, nonce) | `vega-governance-jacket-sdk` gates; `scrambler.require_commitment()` checks minted, unexpired, action="rotate_keys", never used |
| Seal pipeline → Custody (DAG) | Stage records (capsule, layer1, layer2, lineage-root, proof-tierN, SEAL_AUDIT, SEAL_ROTATED) | `vega-custody-sdk` DAG append-only; superproof writes in order, never rewrites |
| Seal pipeline → Custody (Ledger) | Signed top root commitment (SUPERPROOF_ROOT) | `vega-custody-sdk` ledger mints; `verify_seal` checks `ledger.verify()` |
| Configuration → Seal | Preset card (tier, layers, signature alg) | `presets.preset_card()`; hash recorded in audit; `verify_seal` checks preset hash matches |
| Tier backend → Pipeline | Proof (prove/verify) | `proof_tierN.require_prover()` raises `TierUnavailable` if not registered; registration deliberate (`replace=True`) |
| Signature algorithm → Pipeline | Sign/verify top root | `signature.verify_root(expected_alg=...)` — algorithm from CONFIG, not from signature object |
| Key rotation → Chain | ROTATION entry (old_key_id, new_key_id, commitment_leaf, retired) | `scrambler.commit_rotation()` checks old key id not already retired; `require_commitment()` checks single-use |
| Reseal → Chain | SEAL_ROTATED entry (old_top_root, new_top_root, key ids) | `rotation.reseal()` records after new seal; old seal remains valid history |
| Verifier → Seal | `accept_tiers`, `require_signature` | `verify_seal()` enforces verifier's minimums; seal cannot vouch for its own strength |

The model (any AI/agent) never holds signing keys, never mints commitments, never chooses proof tier — the configuration and human commitment do. Every step lands in the append-only chain that anyone can verify without trusting the model, the vendor, or the project.