# Security Hardening Evidence

This document records the hardening actions performed for CryptoFlex v0.5.2.

## Added Test Helpers
- `tests/adversarial/test_pqc_unavailable.py` verifies graceful handling when liboqs is disabled via `CRYPTOFLEX_DISABLE_PQC=1`.
- Existing `MockPQCSource` provides a deterministic, non‑cryptographic PQC stand‑in for testing.

## Test Organization
- New adversarial tests are placed under `tests/adversarial/` to keep the main test suite tidy.

## Documentation Links
- README.md now links to this file.
- SECURITY.md now links to this file.

*No changes were made to cryptographic implementations or security claims.*
