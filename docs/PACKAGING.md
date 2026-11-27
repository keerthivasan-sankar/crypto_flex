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
*   **Reproducibility Verification:** Automated double-build reproducibility checking via `scripts/verify_reproducibility.py`. Release builds are verified within the controlled GitHub Actions build environment using the pinned build toolchain (`pip==26.2.1`, `setuptools==84.0.0`, `wheel==0.48.0`, `build==1.6.0`) and fresh isolated build environments. The release hard gate verifies deterministic wheel output within the controlled build procedure, deterministic raw sdist output within the controlled build procedure, and parity between the verifier rebuild and the release-run reference artifacts. This verification reflects controlled pipeline determinism and does not constitute independent multi-machine reproduction, an independent cryptographic audit, or a formal supply-chain security certification.
*   **SHA-256 Checksum Manifests:** `SHA256SUMS.txt` is generated in `dist/` covering all distribution artifacts, release metadata, and both runtime SBOMs.
*   **Software Bill of Materials (SBOM):** Release CI (`.github/workflows/build-wheels.yml`) generates authoritative **CycloneDX 1.5 JSON Runtime SBOMs** for both classical (`dist/SBOM.json`) and PQC-enabled (`dist/SBOM-pqc.json`) runtime environments. The SBOMs are generated from clean environments installing the built wheel, normalized with `scripts/normalize_sbom.py` (removing bootstrap installer packages and establishing explicit leaf dependencies), and strictly validated with `scripts/verify_sbom.py` (verifying schema conformance, graph completeness, root reachability, and two-way runtime inventory reconciliation). For details, see [docs/SBOM.md](SBOM.md).
*   **Build Provenance Attestation:** Automated GitHub Actions build provenance attestation via `actions/attest-build-provenance` covering all artifacts in `./dist/*`.

### 2.2 Future / Planned Enhancements
*   **Platform-Specific Native Bundles:** If enterprise demand requires it, future releases may explore distributing self-contained binary wheels embedding pre-compiled `liboqs` shared objects (using `cibuildwheel`).
*   **Cosign / Sigstore Key Signing:** External GPG/Cosign signing of checksum manifests for PyPI/Sigstore distribution.

---

## 3. Independent Multi-Machine Reproduction Procedure

### 3.1 Defining Independent Reproduction vs. Controlled Reproducibility
It is essential to distinguish between two distinct forms of reproducibility:

1. **Controlled Reproducibility (In-Pipeline):**
   Repeated builds executed inside the controlled GitHub Actions release runner using isolated virtual environments. This verifies that the release pipeline itself is internally deterministic. Two jobs or builds executed on the same runner environment are **not** independent machines.
2. **Independent Multi-Machine Reproduction:**
   A distinct external machine or environment independently retrieves the exact tagged source commit and executes the documented build procedure using its own host Python and clean isolated build environment, without access to or influence from the original release runner's cached state, global site-packages, or filesystem.

> [!IMPORTANT]
> **Status of Claims:**
> The repository provides a documented procedure for independent multi-machine reproduction. Independent reproduction is considered demonstrated only when an external machine/environment produces matching artifacts for the specified release.

### 3.2 Target Release Baseline (v0.5.4)
The official baseline release artifacts were generated by GitHub Actions Build Package run `36244912921`:

* **Release Tag:** `v0.5.4`
* **Commit SHA:** `72ea01776b6d8390fb4c3993724853d7c50c8543`
* **SOURCE_DATE_EPOCH:** `1790428894`
* **Pinned Build Toolchain:**
  * `pip==26.2.1`
  * `build==1.6.0`
  * `setuptools==84.0.0`
  * `wheel==0.48.0`
* **Reference Artifact Hashes (Ubuntu 24.04, Python 3.11.16 x64):**
  * **Wheel (`cryptoflex-0.5.4-py3-none-any.whl`):**
    * Size: `43924` bytes
    * SHA-256: `97c74a58487766c987d4be413d7905bfa9101ccdcbceeec64c9df7406aa62794`
  * **Source Distribution (`cryptoflex-0.5.4.tar.gz`):**
    * Size: `64885` bytes
    * SHA-256: `91c8f595cbcba6bb82ee71fd4997f01908889d3346f0e0bdef8da653a697763f`

### 3.3 Platform Independence & Differences
* **Universal Pure-Python Wheel:** CryptoFlex contains no native compiled C extensions in its package distribution (`pyproject.toml` uses `setuptools.build_meta`). It produces a universal `py3-none-any.whl` wheel artifact. Across systems sharing compatible zip packaging semantics and standard Python environments, wheel byte parity is expected.
* **Source Distribution (sdist):** The authoritative release build is the Linux CI build (`build-wheels.yml`). Source extraction pins `git -c core.autocrlf=false -c tar.umask=0022 archive`, so file modes and line endings do not depend on the builder's git configuration. With these pins, CI-style extraction and direct builds produced byte-identical raw wheel and sdist artifacts in local Linux checks, including across different `tar.umask` settings in the environment.
* **Windows builds are diagnostic only.** Windows has no POSIX file modes, so its archives carry different modes (for example `0666` instead of `0644`). Do not compare Windows hashes with the Linux CI hashes.
* **Hashes depend on the commit.** `SOURCE_DATE_EPOCH` is the commit timestamp, so an amend or cherry-pick changes every artifact hash. Record release hashes only from the final commit.
* **`metadata.json`:** CI writes `dist/metadata.json` (commit SHA, epoch, Python version, pinned tool versions, wheel and sdist SHA-256) with `scripts/generate_release_metadata.py`. `verify-reproducibility.yml` validates it against the published release assets.
* **Reproduction helper.** `scripts/reproduce_release.py` is a separate build path with its own packaging normalization. Its output is not the CI artifact set, and it should not be assumed to match CI hashes without checking.

### 3.4 Step-by-Step Manual Reproduction Procedure
On an independent machine:

1. **Clone and Checkout Exact Tag:**
   ```bash
   git clone https://github.com/keerthivasan-sankar/crypto_flex.git
   cd crypto_flex
   git checkout v0.5.4
   ```
2. **Verify Commit SHA and Clean Working Tree:**
   ```bash
   git rev-parse HEAD
   # Must output: 72ea01776b6d8390fb4c3993724853d7c50c8543
   git status --short
   # Working tree must be completely clean (no uncommitted or untracked changes)
   ```
3. **Set Up a Fresh Isolated Build Environment:**
   ```bash
   python3 -m venv .reproduce_venv
   source .reproduce_venv/bin/activate  # On Windows: .reproduce_venv\Scripts\activate
   pip install --upgrade pip==26.2.1
   pip install build==1.6.0 setuptools==84.0.0 wheel==0.48.0
   ```
   *Note on TLS / CA verification:* Pip commands must use standard HTTPS certificate validation. Do NOT pass `--trusted-host` or disable certificate verification. If certificate validation fails (e.g. on a local Windows machine), resolve the issue by installing or configuring the host's CA certificate bundle rather than disabling TLS verification.
4. **Extract Source Tree via Git Archive:**
   To guarantee that no local repository artifacts, caches, or untracked files leak into the build:
   ```bash
   mkdir -p build_src
   git archive v0.5.4 | tar -x -C build_src
   cd build_src
   ```
5. **Execute Build with Deterministic Timestamp:**
   ```bash
   export SOURCE_DATE_EPOCH=$(git -C .. log -1 --format=%ct 72ea01776b6d8390fb4c3993724853d7c50c8543)
   # Or explicitly: export SOURCE_DATE_EPOCH=1790428894
   python -m build --sdist --wheel --outdir ../reproduced_dist/
   cd ..
   ```
6. **Compute and Record Artifact Hashes:**
   ```bash
   sha256sum reproduced_dist/*
   ```

### 3.5 Automated Reproduction Helper
The repository provides a reproduction helper script (`scripts/reproduce_release.py`) that automates steps 2–6 in an isolated temporary directory.

The helper injects a build-time PEP 517 backend wrapper hook that canonicalizes packaging metadata attributes: LF line endings in metadata files; wheel ZIP file permission attributes (`create_system=3`, `external_attr` normalized to POSIX permission masks); and the sdist gzip container OS byte set to `0x03` (Unix). Under the controlled reproduction procedure this achieves 100% byte-for-byte wheel parity and raw TAR payload parity with the reference artifacts listed in Section 3.2. The underlying cryptographic implementation was not changed by this tooling work.

> **Note:** Cross-platform compressed `.tar.gz` payload differences between Windows and Linux native `zlib` implementations (differing LZSS match tie-breaking in MSVC- vs. GCC-compiled `zlib`) cannot be controlled through Python-level parameters and are not claimed as resolved.

```bash
# Build and verify against official v0.5.4 baseline:
python scripts/reproduce_release.py --target v0.5.4

# Or compare against a local directory containing official release artifacts:
python scripts/reproduce_release.py --target v0.5.4 --reference-dir path/to/official/dist/ --output-json report.json
```

### 3.6 Independent Reproduction Evidence Format
When collecting or submitting independent reproduction evidence, the following format must be used:

```markdown
### Machine A (Official GitHub Actions Release Runner):
* OS: Ubuntu 24.04 (Linux 6.8.0-1017-azure x86_64)
* Python: 3.11.16 (/opt/hostedtoolcache/Python/3.11.16/x64)
* Architecture: x86_64
* Git SHA: 72ea01776b6d8390fb4c3993724853d7c50c8543
* Wheel Filename: cryptoflex-0.5.4-py3-none-any.whl
* Wheel Size: 43924 bytes
* Wheel SHA-256: 97c74a58487766c987d4be413d7905bfa9101ccdcbceeec64c9df7406aa62794
* sdist Filename: cryptoflex-0.5.4.tar.gz
* sdist Size: 64885 bytes
* sdist SHA-256: 91c8f595cbcba6bb82ee71fd4997f01908889d3346f0e0bdef8da653a697763f

### Machine B (Independent Reproduction Host):
* OS: [e.g. Debian 12 / Fedora 40 / macOS 14 / Ubuntu 22.04]
* Python: [e.g. 3.11.x / 3.12.x]
* Architecture: [e.g. x86_64 / aarch64]
* Git SHA: [Must match 72ea01776b6d8390fb4c3993724853d7c50c8543]
* Wheel Filename: cryptoflex-0.5.4-py3-none-any.whl
* Wheel Size: [size in bytes]
* Wheel SHA-256: [hash]
* sdist Filename: cryptoflex-0.5.4.tar.gz
* sdist Size: [size in bytes]
* sdist SHA-256: [hash]

### Comparison & Verification:
* Source SHA matches: [YES / NO]
* Wheel hash matches: [YES / NO]
* sdist hash matches: [YES / NO]
* Result: [REPRODUCED / MISMATCH]
```

---

## 4. CryptoFlex v0.5.5 Historical Candidate Build Evidence (Run 45432803464)

The following section preserves the historical candidate build outputs from an earlier GitHub Actions release CI run on `main`.

> [!IMPORTANT]
> **Historical Candidate Build Status (Commit `f4bc71d2a55f6037585c19887901bff24653d760`, Run `45432803464`)**
> The Build Package workflow (`.github/workflows/build-wheels.yml`) supports both `push` on `v*` release tags and manual `workflow_dispatch` triggers. The artifacts and hashes below are **historical candidate-build evidence** from a manually dispatched `workflow_dispatch` run (Run `45432803464` at commit `f4bc71d2a55f6037585c19887901bff24653d760`). They are **not** the hashes of final-main local validation builds (such as commit `8d6dd3344428af8f784a70dfbddb884b7e50988e`), and they do **not** constitute an explicitly authorized tag-based release, published GitHub Release, or PyPI publication. Independent multi-machine reproduction has not yet been conducted for v0.5.5.

### 4.1 Candidate Build Parameters
* **Workflow:** Build Package (`.github/workflows/build-wheels.yml`)
* **Run ID:** `45432803464`
* **Trigger:** `workflow_dispatch`
* **Branch:** `main`
* **Candidate Commit SHA:** `f4bc71d2a55f6037585c19887901bff24653d760`
* **Environment:** Ubuntu 24.04 (`ubuntu-24.04`), Python 3.11 (`actions/setup-python@v5`)
* **Pinned Toolchain:**
  * `pip==26.2.1`
  * `build==1.6.0`
  * `setuptools==84.0.0`
  * `wheel==0.48.0`
  * `cyclonedx-bom==4.1.2`
  * `jsonschema==4.23.0`

### 4.2 Candidate Artifact Hashes & Checksums
All files generated into `./dist/` were verified by `scripts/verify_reproducibility.py` and `scripts/verify_sbom.py`, checksummed in `dist/SHA256SUMS.txt`, uploaded as `python-package-distributions`, and attested via GitHub Actions provenance:

| Artifact File | Description | SHA-256 Checksum |
| :--- | :--- | :--- |
| `cryptoflex-0.5.5-py3-none-any.whl` | Universal pure-Python wheel | `ead679dfbdb529f4f63b5620c58c43afd0581398c9190a2339d8678403b6f5fe` |
| `cryptoflex-0.5.5.tar.gz` | Source distribution (sdist) | `53624d33a671e8499e211e042a8a4505337d15a49dd45c022cdbb7c33881cd19` |
| `dist/SBOM.json` | CycloneDX 1.5 Base Runtime SBOM | `78222038bfe31f944942fb6652444d0c3b0a58fbb76353a5814e9d8e041ff52f` |
| `dist/SBOM-pqc.json` | CycloneDX 1.5 PQC Runtime SBOM | `c86db632b1ff170e36b2ff723b551bca329c0a518799e0ace8fc481c314d629f` |
| `dist/metadata.json` | Release metadata manifest | `d402d91120b48f7c06b9e4aeea1a44805418569cc987eb65cd889f8eaa8092b5` |
| `dist/SHA256SUMS.txt` | Checksum manifest of all dist files | `6f687bca84348cef4635b475681eb7095b00a3866305f035b393c58fb2226d04` |
| Provenance Attestation | SLSA build provenance | Attested via `actions/attest-build-provenance` on `./dist/*` |
