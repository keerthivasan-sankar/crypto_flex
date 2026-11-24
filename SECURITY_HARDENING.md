# Security Hardening Evidence

> **Historical Context:** Sections 1–4 of this document record the security-hardening actions and scope boundaries established for CryptoFlex v0.5.4. For the supply-chain and SBOM validation improvements introduced in v0.5.5, see [Section 5: v0.5.5 Supply-Chain Integrity Addendum](#5-v055-supply-chain-integrity-addendum).

## 1. Added Test Helpers (v0.5.4)
- `tests/adversarial/test_pqc_unavailable.py` verifies graceful handling when liboqs is disabled via `CRYPTOFLEX_DISABLE_PQC=1`.
- Existing `MockPQCSource` provides a deterministic, non‑cryptographic PQC stand‑in for testing.

## 2. Test Organization (v0.5.4)
- New adversarial tests are placed under `tests/adversarial/` to keep the main test suite tidy.

## 3. Reproducibility Verification & Scope (v0.5.4)
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

A documented procedure and evidence framework for independent multi-machine reproduction is provided in [docs/PACKAGING.md](docs/PACKAGING.md#3-independent-multi-machine-reproduction-procedure) and [`scripts/reproduce_release.py`](scripts/reproduce_release.py). Independent reproduction is considered demonstrated only when an external machine/environment produces matching artifacts for the specified release.

### Developer Troubleshooting: TLS / CA Verification
Build environment isolation uses normal HTTPS certificate verification without `--trusted-host` or TLS bypasses. If a local developer environment (such as a local Windows host) encounters CA certificate verification errors during fresh virtual environment setup, resolve them through the host machine's trusted certificate store or network configuration rather than disabling TLS verification.

## 4. Memory Lifecycle & Best-Effort Zeroization (v0.5.4)
- CryptoFlex performs best-effort zeroization of mutable secret buffers that it directly controls (e.g., derived root keys, wrapping keys, and temporary serialized private key buffers during keystore export/import and encryption/decryption routines).
- Zeroization is executed in `finally` blocks using `cryptoflex.utils.zeroize()` (in-place `ctypes.memset` over mutable `bytearray` and writable `memoryview` instances) to ensure cleanup occurs on both success and exception paths.

### Residual Memory Limitations
- **Immutable Python Bytes:** Python `bytes` objects are immutable and managed by CPython's allocator/garbage collector. Intermediate immutable `bytes` values (such as raw HKDF inputs/outputs or decoded base64 strings before mutable conversion) cannot be overwritten in place and remain until garbage collection or reallocation.
- **Dependency & Native Memory Lifecycle:** X25519 private keys and ML-KEM secret keys are held inside underlying dependency objects (`cryptography`'s `X25519PrivateKey` OpenSSL structures and `liboqs-python`'s `KeyEncapsulation` C library allocations). Native/C-level memory destruction is controlled by those upstream libraries.

---

## 5. v0.5.5 Supply-Chain Integrity Addendum

CryptoFlex v0.5.5 introduces enhanced build-integrity and software supply-chain controls enforced in release CI (`.github/workflows/build-wheels.yml`):

### 5.1 CycloneDX 1.5 Runtime SBOMs
- Generates separate Base Runtime (`dist/SBOM.json`) and PQC Runtime (`dist/SBOM-pqc.json`) SBOMs directly from isolated environments installing the built wheel.
- Excludes installer/bootstrap packages (`pip`, `setuptools`, `wheel`) via deterministic normalization (`scripts/normalize_sbom.py`).
- Enforces explicit dependency arrays (`"dependsOn": []`) for terminal leaf packages.
- Fails closed if any non-bootstrap component depends on a bootstrap package (`NormalizationRefused`).

### 5.2 Strict Verification Gate (`scripts/verify_sbom.py`)
- Enforces official CycloneDX 1.5 JSON Schema (Draft-07 standard) validation.
- Validates unique `bom-ref` registry across all components.
- Enforces full graph connectivity and root reachability (rejecting orphan components).
- Performs two-way runtime inventory reconciliation against `pip list --format=json`.
- Detects scanner/build-tool contamination.

### 5.3 Provenance and Release Hard Gates
- Release workflow hard gate runs double-build reproducibility checking via `scripts/verify_reproducibility.py`.
- Generates `dist/RELEASE_METADATA.json` binding commit SHA, timestamp (`SOURCE_DATE_EPOCH`), and toolchain pins.
- Computes `dist/SHA256SUMS.txt` covering all distribution artifacts, metadata, and both validated SBOMs.
- Attests cryptographic build provenance using GitHub Actions (`actions/attest-build-provenance`).

> [!NOTE]
> **Scope Disclaimer:** While these supply-chain controls provide high assurance of package determinism, dependency transparency, and build provenance, they do **not** constitute a formal cryptographic security audit or mathematical proof of the underlying algorithms or combiner design.

## 6. Documentation Links
- [README.md](README.md)
- [Software Bill of Materials (SBOM)](docs/SBOM.md)
- [Packaging & Supply Chain Distribution](docs/PACKAGING.md)
*No changes were made to cryptographic implementations or security claims.*
