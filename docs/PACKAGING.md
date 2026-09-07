# Packaging & Supply Chain Distribution

This document specifies the packaging strategy and supply chain security roadmap for `cryptoflex`.

---

## 1. Current Packaging Model (Pure Python)

`cryptoflex` is distributed as a **pure-Python package** (universal wheel `py3-none-any.whl` and source distribution `sdist`). 

The library does not contain any native C extensions itself. It wraps the standard `cryptography` package for classical algorithms, and optionally interfaces with `liboqs-python` for post-quantum cryptography.

### 1.1 Dependency Resolution
*   **Classical Mode (Default):** Requires only the `cryptography` package.
*   **Post-Quantum Mode:** Requires the optional `[pqc]` extra, which installs `liboqs-python`. 

**Important:** The `liboqs-python` package itself relies on a native C library (`liboqs`). Provisioning the native `liboqs` shared objects for your specific platform/OS is treated as an external operational requirement for now.

### 1.2 Automated Build Pipeline
Our GitHub Actions CI pipeline (`.github/workflows/build-wheels.yml`) automatically builds and publishes the pure-Python distribution artifacts for each release tag using standard Python build tools:

```bash
python -m build --sdist --wheel --outdir dist/
```

---

## 2. Planned Supply Chain Security Roadmap

The following supply-chain transparency and security features are planned for future, post-audit releases:

### 2.1 Platform-Specific Native Bundles
If enterprise demand requires it, future releases may explore distributing fully self-contained binary wheels that embed pre-compiled `liboqs` shared objects for major target architectures (using `cibuildwheel`), removing the need for external native provisioning.

### 2.2 Software Bill of Materials (SBOM)
We currently provide a static `docs/SBOM.md` reference document. In the future, this will be automated to generate an exact, dynamically-resolved CycloneDX/SPDX SBOM detailing all transitive Python dependencies and native cryptographic primitives for every build environment.

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
