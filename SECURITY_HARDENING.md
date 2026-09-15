# Security Hardening Evidence

This document records the hardening actions performed for CryptoFlex v0.5.2.

## Added Test Helpers
- `tests/adversarial/test_pqc_unavailable.py` verifies graceful handling when liboqs is disabled via `CRYPTOFLEX_DISABLE_PQC=1`.
- Existing `MockPQCSource` provides a deterministic, non‑cryptographic PQC stand‑in for testing.

## Test Organization
- New adversarial tests are placed under `tests/adversarial/` to keep the main test suite tidy.

## Reproducibility Verification
- Automated double-build verification script (`scripts/verify_reproducibility.py`) creates separate fresh build virtual environments populated with pinned build dependencies (`pip==26.2.1`, `setuptools==84.0.0`, `wheel==0.48.0`, `build==1.6.0`).
- Verifies byte-for-byte SHA-256 identity across isolated builds for both wheel (`.whl`) and source distribution (`.tar.gz`) artifacts using deterministic timestamp normalization (`SOURCE_DATE_EPOCH`).

## Documentation Links
- README.md now links to this file.
*No changes were made to cryptographic implementations or security claims.*
