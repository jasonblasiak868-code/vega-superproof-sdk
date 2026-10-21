# vega-superproof-sdk
![vega-superproof-sdk](assets/tile.svg)

<!-- vega-install-order -->
> **Build order: 2/2. This kit needs 1 other Vega kit installed first.** Install them in this order, then this one:
> 1/2 `vega-custody-sdk`  
> 2/2 `vega-superproof-sdk` (this kit)
> Install each with `pip install --no-deps git+https://github.com/jasonblasiak868-code/<name>` in the order shown, plus `pip install cryptography`. Full steps: [INTEGRATION_GUIDE](https://github.com/jasonblasiak868-code/vega-umbrella-sdk/blob/main/INTEGRATION_GUIDE.md).
Layer 2 of the Vega organism: layered sealing with dual lineage and four proof tiers — integrity, privacy (zero-knowledge), quantum-proof (hash-based signature), and locked compute with updating encryption. The seal writes every stage to an append-only DAG before the next stage runs, never downgrades a tier, and only the signed top root reaches the ledger.

> **Licensing.** Source-available, not open source. Free for personal use; free for registered small businesses (under US$1M revenue and valuation); everyone else needs a commercial license (see LICENSE; for a commercial license write to jasonblasiak.ai.mail@gmail.com). Patent pending. Draft licence text, not yet reviewed by an attorney.

## Table of Contents
- [What this is](#what-this-is)
- [Specifications](#specifications)
- [End-to-end functions](#end-to-end-functions)
- [Controls](#controls)
- [What it CANNOT do](#what-it-cannot-do)
- [Platform support](#platform-support)
- [Standalone & unified install](#standalone--unified-install)
- [Diagnostic control](#diagnostic-control)
- [Fail-closed constraints & custom constraints](#fail-closed-constraints--custom-constraints)
- [Where it sits in the family](#where-it-sits-in-the-family)
- [Quick start](#quick-start)
- [Tests](#tests)
- [Status & honesty](#status--honesty)

## What this is
**vega-superproof-sdk** is the *seal* layer (Layer 2) of the Vega SDK family. It takes a capsule from `vega-custody-sdk`, encrypts it in two authenticated layers (AES-256-GCM then ChaCha20-Poly1305), binds the content and the keys into a dual-lineage root, produces a proof at one of four tiers, signs the top root, mints it to the ledger, and records an audit entry with the tier and configuration hash. The tier is enforced by code — a tier 1–3 seal literally cannot be produced without a registered prover backend — and the seal pipeline fails closed: any unavailable tier, signature algorithm, or weak key raises before any DAG or ledger write.

## Specifications

| Item | Value |
|------|-------|
| Version | 0.1.0 |
| Python | ≥3.10 |
| Dependencies | `cryptography≥42`, `vega-custody-sdk` |
| Status | PARTIAL (STATUS.md) — tiers 1–3 require explicit backend registration; SNARK/STARK, ML-DSA/SLH-DSA, full FHE are DESIGN ONLY |
| Tests | 102 tests in 5 files, all passing (STATUS.md) |
| Layer | 2 (seal) — depends on Layer 0 (custody) only |
| License | Source-available, patent pending (U.S. provisional 64/178,949 and others) |

## End-to-end functions
1. **Input**: a `vega-custody` capsule, two 32-byte layer keys, a signing key pair, a DAG, a ledger, and a preset name.
2. **Validate**: keys, preset, tier availability, signature algorithm availability — all up front.
3. **Fail closed**: if any check fails, raise `TierUnavailable`, `SignatureUnavailable`, or `SealError` — nothing is written.
4. **Record capsule stage** to DAG.
5. **Two-layer seal**: AES-256-GCM (key1) then ChaCha20-Poly1305 (key2) with algorithm tags, nonces, AAD, and ciphertext digests.
6. **Record layer1 and layer2 stages** to DAG.
7. **Build dual lineage** (content chain + key-event chain) → lineage root.
8. **Record lineage-root stage** to DAG.
9. **Produce proof** at requested tier (0–3) via registered backend; tier 0 is built-in.
10. **Record proof-tier{N} stage** to DAG.
11. **Compute top root** = SHA-256(proof_binding || lineage_root || preset_hash).
12. **Sign top root** with configured algorithm (Ed25519 built-in; hashsig-sha256-w16 built-in; ML-DSA/SLH-DSA are DESIGN ONLY interfaces).
13. **Mint signed top root** to ledger as `SUPERPROOF_ROOT` commitment.
14. **Write SEAL_AUDIT** to DAG with tier, preset_hash, top_root, and mint receipt.
15. **Return sealed dict** containing envelope, proof, lineage_root, top_root, signature, preset, and audit entry.
16. **Verify**: `verify_seal()` checks proof binding, top root, signature, ledger mint, and enforces verifier's `accept_tiers` and `require_signature` minimums.
17. **Open**: `open_seal()` decrypts both layers with both keys and returns the capsule.

## Controls
- **Preset** (via `presets.preset_card()`): selects tier, layer algorithms, signature algorithm, and note. Seven named presets: `standard` (tier 0, Ed25519), `high_assurance` (tier 1, Ed25519), `maximum` (tier 2, ml-dsa-65), `private` (tier 1, Ed25519), `quantum_proof` (tier 2, hashsig-sha256-w16), `locked_compute` (tier 3, hashsig-sha256-w16), `post_quantum` (tier 0, ml-dsa-65).
- **Tier backend registration** (via `builtin.enable_privacy()`, `builtin.enable_quantum_proof()`, `builtin.enable_locked_compute()`): must be called deliberately at startup; tiers 1–3 fail closed without it.
- **Signature backend registration** (via `signature.register()`): Ed25519 is built-in; `hashsig-sha256-w16` via `hashsig.register()`; post-quantum algorithms are DESIGN ONLY interfaces.
- **Key generation**: `layers.generate_key()` returns 32 random bytes; `validate_keys()` refuses identical or patterned keys.
- **Key rotation**: `scrambler.rotate()` requires a fresh, minted, single-use human commitment for `action="rotate_keys"`; old key id retired on chain.
- **Updating encryption**: `rotation.KeyRatchet` derives epoch keys via HMAC-SHA256; `rotation.reseal()` opens old seal, seals under new keys, writes `SEAL_ROTATED` linking old and new top roots.
- **LWE operations**: `lwe.KeyHolder` encrypts/decrypts; `add`/`sub`/`scale`/`dot`/`total`/`switch` operate on ciphertexts only; noise budget enforced.
- **Shamir split**: `keysplit.split_roles()` (2-of-3: TPM, card, human); `combine_checked()` verifies reconstruction.
- **Selective disclosure**: `disclosure.commit_record()` / `disclose()` / `verify_disclosure()` — salted Merkle tree, padded, shuffled.
- **Zero-knowledge**: `zk.commit()`, `prove_knowledge()`, `prove_range()`, `prove_at_least()`, `attest()` — classical security only (secp256k1 discrete log).

## What it CANNOT do
- Does not make a model aligned, truthful, or kind — it limits what a model can do, not what it believes.
- Not a finished product — working reference implementation with tests; not hardened for production.
- No expert has reviewed the cryptography — plain Python written for clarity, not constant-time.
- Not a security review or containment system — containment is process-level, not an OS sandbox.
- License matrix is policy, not legal advice; draft licence not reviewed by an attorney.
- **general-purpose SNARK/STARK provers, standardized PQ signatures (ML-DSA/SLH-DSA), and full FHE are DESIGN ONLY** — their interfaces fail closed (STATUS.md).
- LWE is additive only: no ciphertext×ciphertext, no encrypted comparisons.
- **Quantum-proof here means the seal rests only on hashes and 256-bit symmetric keys; the zero-knowledge tier (tier 1) relies on discrete log and is NOT quantum-proof.**
- Hash signature is stateful: each key is used once; the state file must never be copied or restored from an old backup.
- Tier 0 is integrity and binding only — never zero-knowledge, never silently downgrades.
- Python cannot truly wipe memory — old keys are released, not scrubbed; for hard guarantees use a hardware module.

## Platform support

| Capability | Platform | Notes |
|------------|----------|-------|
| Core seal (layers, lineage, tier 0, Ed25519, hashsig, disclosure, zk, keysplit, scrambler, rotation, lwe) | Runs anywhere CPython 3.11+ runs: Windows, macOS, Linux | Pure Python via `cryptography` library |
| LWE default params (n=512, q=2^48) | Runs anywhere CPython 3.11+ runs | Pure Python; marked `insecure=False` |
| LWE small test params (n<256) | Runs anywhere CPython 3.11+ runs | Marked `insecure=True` deliberately |
| hashsig state file (disk I/O) | POSIX and Windows | Atomic write via tmp+fsync+replace; works on both |
| FHE full backend (ML-DSA/SLH-DSA, full FHE) | DESIGN ONLY | Interface fails closed; no backend shipped |
| general-purpose SNARK/STARK provers | DESIGN ONLY | Interface fails closed; no backend shipped |
| Native mobile (.apk/.ipa) | **No native mobile build** | The SDK is pure Python and can run inside a Python runtime on Android (Termux) or Apple platforms (BeeWare/Kivy) where that runtime supports its dependencies |

## Standalone & unified install
### Standalone
```bash
pip install -e .
```
Installs and runs alone with `vega-custody-sdk` as its only declared dependency (layer 0). No other family SDKs are imported.

### Unified
Registered in `vega-umbrella-sdk`'s registry as Layer 2 (seal), depending on `custody`:
```
vega-superproof-sdk | 2 seal | custody
```
The umbrella resolves inter-SDK wiring; this kit consumes `vega-custody-sdk` for capsules, DAG, and ledger.

## Diagnostic control
- **CLI entry points**: None published (no `console_scripts` in pyproject.toml).
- **Status/introspection**: `proof_tier1.available()`, `proof_tier2.available()`, `proof_tier3.available()`, `fhe.available()`, `signature.supported()`, `hashsig.Signer.remaining`.
- **Log surfaces**: DAG records every stage (`STAGE:capsule`, `STAGE:layer1-...`, `STAGE:layer2-...`, `STAGE:lineage-root`, `STAGE:proof-tierN`, `SEAL_AUDIT`, `SEAL_ROTATED`, `ROTATION`).
- **Exit codes**: Test runner exits 0 on pass, 1 on fail.
- **Fail-closed indicators**: `TierUnavailable`, `SignatureUnavailable`, `SealError`, `RotationRefused`, `FHEUnavailable`, `NoiseBudgetExhausted`, `LweError`, `HashSigError`, `ZKRefused`, `DisclosureRefused` — all raised before any record write.
- **Environment variables**: None honored by published code.

## Fail-closed constraints & custom constraints
**Fail-closed workflow** (every seal):
1. Validate keys, preset, tier, signature algorithm — **before any DAG write**
2. If tier > 0: `proof_tierN.require_prover()` raises `TierUnavailable` if no backend registered
3. If signature algorithm not in `signature.supported()`: raises `SignatureUnavailable`
4. If keys weak/identical: raises `ValueError`
5. Only after ALL checks pass: enter DAG-writing phase

**Fail-closed constraint points** (module + function):
- `superproof.seal()` lines 47–57: up-front validation of keys, preset, tier, prover, signature alg
- `proof_tier1/2/3.require_prover()`: raises `TierUnavailable` if backend not registered
- `signature.verify_root(expected_alg=...)`: enforces algorithm from CONFIG, not from signature object
- `scrambler.require_commitment()`: checks commitment minted, unexpired, action=`rotate_keys`, single-use
- `lwe._guard()`: raises `NoiseBudgetExhausted` before operation that would exceed limit
- `hashsig.Signer.sign()`: persists index to disk BEFORE returning signature; refuses backwards/reuse
- `rotation.reseal()`: refuses same keys; refuses wrong old keys

**Custom constraints**: This version publishes no user-defined constraint hooks; constraints are fixed by the module and the jurisdiction floor (vega-jurisdiction-sdk). The governing rule: *"User-defined constraints may be STRICTER than the legal minimum for the applicable jurisdiction, never looser. Jurisdictional legal minimums are defined by the jurisdiction registry (vega-jurisdiction-sdk); a custom constraint that would drop below a registered minimum is rejected at the gate."*

## Where it sits in the family
Layer 2 (seal) depends on Layer 0 (custody) for capsules, DAG, and ledger. Layers 3+ (pareah, two-gate, harness, etc.) consume superproof's sealed envelopes, audit entries, and verification results.

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

One family, one organism: every SDK owns exactly one concern and uses the owner of every other concern instead of growing its own copy.

## Quick start
```bash
# From the repo root, with vega-custody-sdk also on PYTHONPATH:
PYTHONPATH=src:../vega-custody-sdk/src python3 -c "
from vega_superproof.seal import layers, superproof, signature
from vega_custody.capsule import capsule as cap
from vega_custody.dag.dag import Dag
from vega_custody.ledger.backend_local import LocalBackend
from vega_custody.ledger.ledger import Ledger
import tempfile, pathlib, secrets

t = pathlib.Path(tempfile.mkdtemp())
dag = Dag([t / 'c.jsonl'], [t / 'l.jsonl'])
led = Ledger([LocalBackend(t / 'led.jsonl')])
sk, pub = signature.new_ed25519()
k1, k2 = layers.generate_key(), layers.generate_key()
c = cap.make('hello world', {'source': 'user'})
sealed = superproof.seal(c, k1, k2, sk, pub, dag, led, 'standard')
print('seal ok, tier:', sealed['proof']['tier'])
print('verify:', superproof.verify_seal(sealed, pub, led))
opened = superproof.open_seal(sealed, k1, k2)
print('opened prefix:', opened['prefix_hash'])
"
```

## Tests
- 102 tests in 5 files, all passing (STATUS.md)
- REVIEW.md: 52 tests ran, ok; 3 test files + 2 redteam files
- Run:
```bash
PYTHONPATH=src:../vega-custody-sdk/src python3 tests/test_seal.py
PYTHONPATH=src:../vega-custody-sdk/src python3 tests/redteam_1_seal_verification.py
PYTHONPATH=src:../vega-custody-sdk/src python3 tests/redteam_2_keys_backends_rotation.py
PYTHONPATH=src:../vega-custody-sdk/src python3 tests/redteam_3_upper_tiers.py
```

## Status & honesty
Reference implementation, work in progress, not independently security-reviewed, crypto not expert-reviewed. PARTIAL: tiers 1–3 require explicit backend registration (`builtin.enable_*()`); general-purpose SNARK/STARK provers, ML-DSA/SLH-DSA, and full FHE are DESIGN ONLY with fail-closed interfaces. This kit details one branch of a broader filed architecture. The remaining branches are the subject of filed disclosures and are outside the scope of this repository.
