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
Our GitHub Actions CI pipeline (`.github/workflows/build-wheels.yml`) automatically builds and uploads pure-Python distribution artifacts as workflow artifacts for each release tag:

```bash
python -m build --sdist --wheel --outdir dist/
```

---

## 2. Supply Chain Security Features & Roadmap

### 2.1 Implemented Supply Chain Controls
*   **Reproducibility Verification:** Automated double-build reproducibility checking via `scripts/verify_reproducibility.py`, verifying byte-for-byte SHA-256 identity of both wheel (`.whl`) and source distribution (`.tar.gz`) artifacts built under deterministic timestamps (`SOURCE_DATE_EPOCH`) with a pinned toolchain (`pip==26.2.1`, `setuptools==84.0.0`, `wheel==0.48.0`, `build==1.6.0`).
*   **SHA-256 Checksum Manifests:** `SHA256SUMS.txt` is generated in `dist/` for all release artifacts.
*   **Software Bill of Materials (SBOM):** Release CI (`.github/workflows/build-wheels.yml`) automatically generates a CycloneDX 1.4 JSON SBOM (`dist/SBOM.json`) using `cyclonedx-bom==4.1.2`, covering the Python build environment. It is a build-environment SBOM, not a product/runtime SBOM, and excludes `cryptography`, `liboqs-python`, and native `liboqs`.
*   **Build Provenance Attestation:** Automated GitHub Actions build provenance attestation via `actions/attest-build-provenance`.

### 2.2 Future / Planned Enhancements
*   **Platform-Specific Native Bundles:** If enterprise demand requires it, future releases may explore distributing self-contained binary wheels embedding pre-compiled `liboqs` shared objects (using `cibuildwheel`).
*   **Cosign / Sigstore Key Signing:** External GPG/Cosign signing of checksum manifests for PyPI/Sigstore distribution.
