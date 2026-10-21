# Changelog

## 2026-10-20: fixes found by a source read

These were found by reading the source against its own documentation after release, not by the earlier test and review passes. Each fix has a regression test in
`tests/test_findings_20261020.py` that failed before the fix, and each fix was checked by undoing it and confirming a test fails. Behaviour that changed is listed under "Changed".

### Fixed
- **Tier names contradicted the code.** The docs and error messages called tier 1 "SNARK" and tier 2 "STARK", but the built-in backends are a Schnorr proof of knowledge (tier 1, privacy) and hash-based quantum-proof sealing (tier 2). Tiers are now named for what the built-in backend is; a general-purpose SNARK or STARK prover could be registered in the same slot, but none is shipped. Presets and error messages were corrected. The `maximum` preset needs an ML-DSA signer, which is not built, so it refuses today (its note now says so).
- **Rotation could be raced.** `rotate` checked "this commitment / this key already used?" and recorded the rotation as two steps, so concurrent rotations could share one commitment or retire one key twice. They now run under one lock per DAG.
- A rotation commitment that was not an object, or had a non-numeric expiry, raised a raw error; it is now a clean refusal.
