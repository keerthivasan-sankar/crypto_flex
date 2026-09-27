# Security Hardening Evidence

This document records the hardening actions and scope boundaries for CryptoFlex v0.5.4.

## Added Test Helpers
- `tests/adversarial/test_pqc_unavailable.py` verifies graceful handling when liboqs is disabled via `CRYPTOFLEX_DISABLE_PQC=1`.
- Existing `MockPQCSource` provides a deterministic, non‑cryptographic PQC stand‑in for testing.

## Test Organization
- New adversarial tests are placed under `tests/adversarial/` to keep the main test suite tidy.

## Reproducibility Verification & Scope
CryptoFlex v0.5.4 is reproducible within the controlled GitHub Actions build environment using the pinned build toolchain (`pip==26.2.1`, `setuptools==84.0.0`, `wheel==0.48.0`, `build==1.6.0`) and isolated build environments.

The automated double-build verification script (`scripts/verify_reproducibility.py`) serves as a release hard gate verifying:
- deterministic wheel output within the controlled build procedure
- deterministic raw sdist output within the controlled build procedure
- parity between the verifier rebuild and the release-run reference artifacts

### Reproducibility Scope
Reproducibility is verified in the controlled GitHub Actions release environment using pinned tooling and fresh isolated environments.
This verification does **not** constitute:
- independent-machine reproduction
- an independent cryptographic audit
- a formal supply-chain security certification

### Developer Troubleshooting: TLS / CA Verification
Build environment isolation uses normal HTTPS certificate verification without `--trusted-host` or TLS bypasses. If a local developer environment (such as a local Windows host) encounters CA certificate verification errors during fresh virtual environment setup, resolve them through the host machine's trusted certificate store or network configuration rather than disabling TLS verification.

## Memory Lifecycle & Best-Effort Zeroization
- CryptoFlex performs best-effort zeroization of mutable secret buffers that it directly controls (e.g., derived root keys, wrapping keys, and temporary serialized private key buffers during keystore export/import and encryption/decryption routines).
- Zeroization is executed in `finally` blocks using `cryptoflex.utils.zeroize()` (in-place `ctypes.memset` over mutable `bytearray` and writable `memoryview` instances) to ensure cleanup occurs on both success and exception paths.

### Residual Memory Limitations
- **Immutable Python Bytes:** Python `bytes` objects are immutable and managed by CPython's allocator/garbage collector. Intermediate immutable `bytes` values (such as raw HKDF inputs/outputs or decoded base64 strings before mutable conversion) cannot be overwritten in place and remain until garbage collection or reallocation.
- **Dependency & Native Memory Lifecycle:** X25519 private keys and ML-KEM secret keys are held inside underlying dependency objects (`cryptography`'s `X25519PrivateKey` OpenSSL structures and `liboqs-python`'s `KeyEncapsulation` C library allocations). Native/C-level memory destruction is controlled by those upstream libraries.

## Documentation Links
- README.md now links to this file.
*No changes were made to cryptographic implementations or security claims.*
