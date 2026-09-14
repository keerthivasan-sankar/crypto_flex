# Packaging & Supply Chain Distribution

This document specifies the packaging strategy and supply chain security roadmap for `cryptoflex`.

---

## 1. Current Packaging Model (Pure Python)

`cryptoflex` is distributed as a **pure-Python package** (universal wheel `py3-none-any.whl` and source distribution `sdist`). 

The library does not contain any native C extensions itself. It wraps the standard `cryptography` package for classical algorithms, and optionally interfaces with `liboqs-python` for post-quantum cryptography.

### 1.1 Dependency & Packaging Model
*   **Pure Python Distribution:** `cryptoflex` is published as a universal pure-Python wheel (`py3-none-any.whl`) and source distribution (`sdist`). It contains no compiled C extensions.
*   **Classical Mode (Default):** Requires only the `cryptography` package.
*   **Post-Quantum Mode:** Requires the `[pqc]` extra, which installs `liboqs-python`.
*   **Native C Library Dependency:** `liboqs-python` requires the native `liboqs` C library. Provisioning `liboqs` shared objects on the host OS is an external deployment requirement.
*   **CI Validation:** In CI (`.github/workflows/tests.yml`), real PQC testing builds native `liboqs` pinned to tag `0.16.0` (commit `5a1a854b0dc9f2141bdc771c555ee60c37950183`).

### 1.2 Graceful Degradation & Security Posture
*   **Fallback Behavior:** If `liboqs` is unavailable or disabled via `CRYPTOFLEX_DISABLE_PQC=1`, `PQCSource.is_available()` returns `False`. The `PolicyEngine` automatically degrades to `classical_only` profile selection.
*   **Security Disclaimer:** Falling back to `classical_only` mode provides classical X25519 security only. It does **NOT** provide post-quantum security and must not be treated as equivalent to hybrid PQC protection against quantum eavesdroppers (Harvest-Now-Decrypt-Later).

### 1.3 Automated Build Pipeline
Our GitHub Actions CI pipeline (`.github/workflows/build-wheels.yml`) automatically builds and publishes pure-Python distribution artifacts for each release tag:

```bash
python -m build --sdist --wheel --outdir dist/
```

---

## 2. Planned Supply Chain Security Roadmap

The following supply-chain transparency and security features are planned for future, post-audit releases:

### 2.1 Platform-Specific Native Bundles
If enterprise demand requires it, future releases may explore distributing fully self-contained binary wheels that embed pre-compiled `liboqs` shared objects for major target architectures (using `cibuildwheel`), removing the need for external native provisioning.

### 2.2 Software Bill of Materials (SBOM)
Release CI (`.github/workflows/build-wheels.yml`) automatically generates a CycloneDX 1.4 JSON SBOM (`dist/SBOM.json`) using `cyclonedx-bom==4.1.2`. The generated SBOM is published alongside release artifacts and included in `SHA256SUMS.txt` checksum coverage. The SBOM documents the Python dependency and build environment boundary. Native `liboqs` remains an external native deployment dependency and is not bundled in the pure-Python wheel. SBOM information provides supply-chain component visibility and is not equivalent to a vulnerability audit or security certification.

### 2.3 Artifact Cryptographic Hashes & Signatures
Future wheels will be accompanied by SHA-256 checksum manifests signed via Cosign/GPG to enable reproducible double-build verification and Sigstore provenance:

```bash
# Planned verification workflow:
sha256sum -c SHA256SUMS

cosign verify-blob \
  --certificate github-actions-cert.pem \
  --signature SHA256SUMS.sig \
  SHA256SUMS
```
