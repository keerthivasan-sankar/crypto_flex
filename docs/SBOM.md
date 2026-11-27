# Software Bill of Materials (SBOM) Specification

**Project:** `cryptoflex`
**Version:** 0.5.5 (Release Candidate)
**Standard:** CycloneDX 1.5 (JSON format)
**Schema Definition:** [`scripts/bom-1.5.schema.json`](../scripts/bom-1.5.schema.json)

> [!IMPORTANT]
> **Runtime SBOM Architecture (v0.5.5)**
> Unlike earlier prototypes that documented build-time environments under CycloneDX 1.4, CryptoFlex v0.5.5 produces authoritative **Runtime SBOMs** under **CycloneDX 1.5**. Two distinct runtime SBOMs are generated from clean, isolated Python virtual environments into which the built pure-Python wheel is installed:
> - `dist/SBOM.json` — Base Runtime SBOM (classical runtime dependencies).
> - `dist/SBOM-pqc.json` — PQC Runtime SBOM (runtime dependencies with the `[pqc]` extra enabled).

---

## 1. Scope & Distribution Boundaries

### 1.1 Base Runtime SBOM (`dist/SBOM.json`)
The Base Runtime SBOM inventories the exact package tree installed when `pip install cryptoflex` is executed in a clean virtual environment:
* **Root Component:** `cryptoflex` (version `0.5.5`).
* **Direct Runtime Dependencies:** `cryptography` (`>=50.0.0,<51.0.0`).
* **Transitive Dependencies:** `cffi`, `pycparser`.
* **Excluded Tooling:** Installer tooling (`pip`, `setuptools`, `wheel`) introduced by `python -m venv` is excluded by the normalizer because it does not constitute a runtime dependency of the packaged library.

### 1.2 PQC Runtime SBOM (`dist/SBOM-pqc.json`)
The PQC Runtime SBOM inventories the complete package tree installed when `pip install cryptoflex[pqc]` is executed in a clean virtual environment:
* **Root Component:** `cryptoflex` (version `0.5.5`).
* **Direct Runtime Dependencies:** `cryptography` (`>=50.0.0,<51.0.0`) and `liboqs-python` (`>=0.16.0,<0.17.0`).
* **Transitive Dependencies:** `cffi`, `pycparser`.
* **Excluded Tooling:** Virtual environment bootstrap packages (`pip`, `setuptools`, `wheel`) are excluded.

### 1.3 External Native Dependency Boundary
`liboqs-python` interfaces with the native `liboqs` C library (`liboqs.so` on Linux, `oqs.dll` on Windows) via CFFI/ctypes. Similarly, `cryptography` relies on native OpenSSL (`libcrypto.so`).
* Because `cryptoflex` is published as a pure-Python wheel (`py3-none-any.whl`), host C dynamic libraries are **external deployment boundaries** provided by the host OS or environment.
* The CycloneDX JSON SBOMs inventory the Python runtime dependency package graph. They do not claim to inventory all native OS shared libraries, which remain an external platform dependency.

---

## 2. Direct & Transitive Dependencies

| Package | Version Constraint | Type | Purpose |
| :--- | :--- | :--- | :--- |
| `cryptoflex` | `0.5.5` | Root Library | Core crypto-agility policy engine and hybrid combiner |
| `cryptography` | `>=50.0.0,<51.0.0` | Direct (Base & PQC) | Classical KEM (X25519), AEAD (AES-256-GCM), KDF (HKDF-SHA384, Argon2id, Scrypt) |
| `cffi` | (resolved by cryptography) | Transitive (Base & PQC) | C Foreign Function Interface for Python |
| `pycparser` | (resolved by cffi) | Transitive (Base & PQC) | C parser in Python |
| `liboqs-python` | `>=0.16.0,<0.17.0` | Direct (PQC only) | Python bindings for native ML-KEM algorithms |

---

## 3. SBOM Normalization (`scripts/normalize_sbom.py`)

When CycloneDX tooling (`cyclonedx-bom==4.1.2`) inspects an installed virtual environment, its raw output includes virtualenv installer packages and may omit explicit dependency arrays for leaf nodes. The deterministic normalizer runs between generation and verification to align the document with CycloneDX 1.5 graph semantics:

1. **Bootstrap Package Removal:**
   - Prunes installer/bootstrap packages (`pip`, `setuptools`, `wheel`) from the `components` list. These packages are created by `python -m venv` and are not runtime dependencies of `cryptoflex`.
   - Never removes or mutates the root component (`cryptoflex`).
2. **Bootstrap Edge Pruning:**
   - Prunes dependency edges originating from bootstrap packages (e.g. `setuptools -> pip` introduced by setuptools testing metadata).
3. **Explicit Leaf Dependency Arrays:**
   - CycloneDX 1.5 uses an explicit empty list (`"dependsOn": []`) to declare that a registered component has no dependencies. When a leaf dependency entry exists without `dependsOn`, the normalizer populates `"dependsOn": []` (e.g. for `pycparser` and `liboqs-python`).
4. **Refusal on Real Dependencies (`NormalizationRefused`):**
   - If any non-bootstrap component lists a bootstrap package in its `dependsOn` array, the normalizer raises `NormalizationRefused` and exits with code 2. It will never silently drop a true runtime dependency.
5. **Determinism and Idempotency:**
   - Normalization preserves JSON formatting (key order, 2-space indentation, original line endings, and trailing newlines).
   - The operation is strictly idempotent: re-running on an already normalized file makes zero changes and does not touch the file on disk.

---

## 4. SBOM Verification (`scripts/verify_sbom.py`)

Release CI enforces strict verification against both normalized SBOM files using a fail-closed verifier:

1. **Schema Validation:**
   - Validates the JSON document against the official CycloneDX 1.5 JSON Schema (Draft-07 standard, [`scripts/bom-1.5.schema.json`](../scripts/bom-1.5.schema.json)) using `jsonschema.Draft7Validator`.
   - Fails closed with `RuntimeError` if the `jsonschema` library is missing.
2. **Component Registry & Unique `bom-ref`:**
   - Checks that the root component and all registered components possess non-empty, unique `bom-ref` identifiers. Rejects duplicate references.
3. **Dependency Graph Completeness:**
   - Requires an explicit dependency entry for every registered component in the document.
   - Enforces explicit `"dependsOn": []` for terminal leaf nodes.
   - Enforces referential integrity: every `ref` and `dependsOn` target must resolve to an existing component in the registry (no dangling edges).
4. **Graph Reachability:**
   - Performs a Breadth-First Search (BFS) starting at the root component.
   - Rejects any disconnected or orphan components not reachable from the root.
5. **Direct Runtime Dependencies:**
   - Confirms that the root component directly depends on `cryptography` in Base, and directly depends on both `cryptography` and `liboqs-python` in PQC.
6. **Two-Way Runtime Inventory Reconciliation:**
   - Executes `pip list --format=json` in the target virtual environment (`.sbom_runtime` and `.sbom_pqc`).
   - Subtracts known bootstrap packages (`pip`, `setuptools`, `wheel`).
   - Asserts strict two-way set equality (`installed_runtime == sbom_components`): flags both missing packages and extraneous packages.
7. **Contamination Check:**
   - Scans component names against known build and scanner packages (`cyclonedx-bom`, `cyclonedx-python-lib`, `jsonschema`, `tomli`, etc.) and rejects any document exhibiting scanner contamination.

### CI Invocation Command
In the GitHub Actions release workflow (`.github/workflows/build-wheels.yml`):

```bash
# Normalize both SBOMs
.sbom_tools/bin/python scripts/normalize_sbom.py dist/SBOM.json dist/SBOM-pqc.json

# Validate both SBOMs against schemas and isolated runtime environments
.sbom_tools/bin/python scripts/verify_sbom.py \
  --base dist/SBOM.json \
  --pqc dist/SBOM-pqc.json \
  --runtime-env .sbom_runtime \
  --pqc-env .sbom_pqc
```

---

## 5. Historical Candidate Build Evidence (Commit `f4bc71d2`, Run `45432803464`)

The v0.5.5 supply-chain pipeline was validated in an earlier GitHub Actions candidate run:

- **Workflow:** Build Package (`.github/workflows/build-wheels.yml`)
- **Run ID:** `45432803464`
- **Branch:** `main`
- **Candidate Commit SHA:** `f4bc71d2a55f6037585c19887901bff24653d760`
- **Event:** `workflow_dispatch`
- **Execution Outcome:** SUCCESS (all steps passed)

### Historical Candidate Artifact Hashes
> [!NOTE]
> The Build Package workflow (`.github/workflows/build-wheels.yml`) supports both `v*` tag pushes and manual `workflow_dispatch` triggers. The cryptographic hashes below are **historical candidate-build audit references** from a manually dispatched `workflow_dispatch` run (Run `45432803464` at commit `f4bc71d2a55f6037585c19887901bff24653d760`). They are distinct from final-main local validation builds (such as commit `8d6dd3344428af8f784a70dfbddb884b7e50988e`) and are **not** explicitly authorized tag-based release artifacts or published release assets.

| Artifact File | Description | SHA-256 Checksum |
| :--- | :--- | :--- |
| `cryptoflex-0.5.5-py3-none-any.whl` | Pure-Python universal wheel | `ead679dfbdb529f4f63b5620c58c43afd0581398c9190a2339d8678403b6f5fe` |
| `cryptoflex-0.5.5.tar.gz` | Source distribution (sdist) | `53624d33a671e8499e211e042a8a4505337d15a49dd45c022cdbb7c33881cd19` |
| `dist/SBOM.json` | CycloneDX 1.5 Base Runtime SBOM | `78222038bfe31f944942fb6652444d0c3b0a58fbb76353a5814e9d8e041ff52f` |
| `dist/SBOM-pqc.json` | CycloneDX 1.5 PQC Runtime SBOM | `c86db632b1ff170e36b2ff723b551bca329c0a518799e0ace8fc481c314d629f` |
| `dist/metadata.json` | Build metadata manifest | `d402d91120b48f7c06b9e4aeea1a44805418569cc987eb65cd889f8eaa8092b5` |
| `dist/SHA256SUMS.txt` | Checksum manifest of all dist files | `6f687bca84348cef4635b475681eb7095b00a3866305f035b393c58fb2226d04` |
| Provenance Attestation | GitHub Actions SLSA Provenance | Created via `actions/attest-build-provenance` |

---

## 6. Cryptographic Algorithms and Primitives

| Primitive Type | Algorithm | Context |
| :--- | :--- | :--- |
| **Classical KEM** | X25519 (RFC 7748) | Classical component of hybrid key exchange |
| **Post-Quantum KEM** | ML-KEM-768 / ML-KEM-1024 (FIPS 203) | Post-quantum component of hybrid key exchange via `liboqs` |
| **KDF (Combiner)** | HKDF-SHA384 (RFC 5869) | Derives symmetric root key from component shared secrets |
| **AEAD** | AES-256-GCM | Encrypts and authenticates file payloads and headers |
| **KDF (Keystore)** | Argon2id (m=32MB, t=3, p=1) / Scrypt | Password derivation for at-rest keystore wrapping |
| **PRNG** | `os.urandom()` | Cryptographic nonce and ephemeral key entropy |
