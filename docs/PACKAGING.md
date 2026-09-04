# Enterprise Packaging & Supply Chain Distribution (cryptoflex v0.4.1)

This document specifies the enterprise packaging strategy, pre-compiled wheel binary distribution model, and supply chain security verification procedures for `cryptoflex`.

---

## 1. Enterprise Readiness & Pre-built Wheel Distribution

### 1.1 The Challenge: Native C Compilation Overhead
Standard installations of post-quantum libraries often require compiling the underlying `liboqs` C shared library from source upon package installation or first import. In enterprise and regulated financial environments (e.g., RBI guidelines, FedRAMP, PCI-DSS):
- Workstations and production servers are often **air-gapped** or restricted from running build tools (C compilers like `gcc`, `clang`, or `MSVC`).
- On-demand C compilation introduces non-deterministic build outputs, dynamic dependency resolution risks, and significant deployment latencies.

### 1.2 The Solution: Vendor-Packaged Platform Wheels
`cryptoflex` eliminates compilation barriers by providing **pre-built binary Python wheels (`.whl`)** containing pre-compiled `liboqs` native shared libraries for major target architectures and operating systems:

| Platform | Architecture | Wheel Tag | Embedded Native Binary |
| :--- | :--- | :--- | :--- |
| **Linux** | `x86_64` | `manylinux_2_28_x86_64` | `liboqs.so` (AVX2 / Vector accelerated) |
| **Linux** | `aarch64` | `manylinux_2_28_aarch64` | `liboqs.so` (NEON accelerated) |
| **macOS** | `arm64` (Apple Silicon) | `macosx_11_0_arm64` | `liboqs.dylib` |
| **macOS** | `x86_64` (Intel) | `macosx_10_15_x86_64` | `liboqs.dylib` |
| **Windows** | `amd64` | `win_amd64` | `oqs.dll` |

---

## 2. Automated Multi-Platform CI Wheel Pipeline

`cryptoflex` utilizes `cibuildwheel` and GitHub Actions to build deterministic, pre-compiled wheels.

### Workflow Configuration (`.github/workflows/build-wheels.yml`)

The CI workflow compiles `liboqs` from pinned C source tags (`v0.10.1`), embeds the shared objects into the wheel runtime directory, and packages self-contained distribution archives.

```yaml
name: Build Enterprise Binary Wheels

on:
  push:
    tags:
      - 'v*'
  workflow_dispatch:

jobs:
  build_wheels:
    name: Build wheels on ${{ matrix.os }}
    runs-on: ${{ matrix.os }}
    strategy:
      matrix:
        os: [ubuntu-latest, windows-latest, macos-latest]

    steps:
      - uses: actions/checkout@v4

      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: '3.11'

      - name: Build liboqs and wheels
        run: |
          pip install cibuildwheel
          cibuildwheel --output-dir wheelhouse

      - name: Upload Artifacts
        uses: actions/upload-artifact@v4
        with:
          name: wheels-${{ matrix.os }}
          path: ./wheelhouse/*.whl
```

---

## 3. Air-Gapped Enterprise Deployment Guide

For deployment inside secure, offline data centers:

### Step 1: Download Release Bundle & Wheelhouse
On an internet-connected staging host, download the pre-compiled wheelhouse and dependencies:

```bash
pip download cryptoflex[pqc] \
  --only-binary=:all: \
  --platform manylinux_2_28_x86_64 \
  --python-version 3.11 \
  --dest ./enterprise_wheelhouse
```

### Step 2: Transfer Artifacts to Air-Gapped Host
Transfer the `./enterprise_wheelhouse` directory to the target environment via approved enterprise artifact transfer mechanisms (e.g., audited USB, internal Nexus / Artifactory repository).

### Step 3: Offline Zero-Compilation Installation
On the air-gapped host, run:

```bash
pip install --no-index --find-links=./enterprise_wheelhouse cryptoflex
```

Verification:
```bash
python -c "import cryptoflex; print(cryptoflex.__version__)"
# Output: 0.4.1
```

---

## 4. Supply Chain Transparency & Security Verification

### 4.1 Software Bill of Materials (SBOM)
Every `cryptoflex` release includes an updated CycloneDX / SPDX SBOM (`SBOM.md`) detailing all direct Python dependencies (`cryptography`, `liboqs-python`), underlying C libraries (`OpenSSL`, `liboqs`), and cryptographic algorithms.

### 4.2 Artifact Cryptographic Hashes & Signatures
Release wheels are accompanied by SHA-256 checksum manifests signed via Cosign / GPG:

```bash
# Verify checksums
sha256sum -c SHA256SUMS

# Verify signature
cosign verify-blob \
  --certificate github-actions-cert.pem \
  --signature SHA256SUMS.sig \
  SHA256SUMS
```
