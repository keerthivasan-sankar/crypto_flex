# Software Bill of Materials (SBOM)

**Project:** `cryptoflex`
**Version:** 0.5.3
**Date:** September 2026

> [!NOTE]
> **Build-Environment SBOM & Reference Document**
> The generated SBOM (`dist/SBOM.json`) describes the build environment used to produce release artifacts (`pip`, `build`, `setuptools`, `wheel`, `cyclonedx-bom`). It is a build-environment SBOM, not a product/runtime SBOM, and does not include `cryptography`, `liboqs-python`, or native `liboqs`.

## 1. Scope & Distribution Boundary

* **Included in CI SBOM (`dist/SBOM.json`):** Python build environment dependencies present during artifact generation (`pip`, `build`, `setuptools`, `wheel`, `cyclonedx-bom`).
* **Excluded from Build-Environment SBOM:** Runtime and external dependencies not installed in the build runner environment (`cryptography`, `liboqs-python`, and native `liboqs` C shared objects). Native `liboqs` remains an external native deployment boundary.

## 2. Direct Python Dependencies

| Package | Version Range | Purpose |
| :--- | :--- | :--- |
| `cryptography` | `>=50.0.0,<51.0.0` | AES-256-GCM, X25519 (Classical KEM), HKDF-SHA384, Scrypt, Argon2id |
| `liboqs-python` | `>=0.16.0,<0.17.0` | Python bindings for liboqs (ML-KEM) |

## 3. Underlying Native C Libraries

| Library | Version | Purpose |
| :--- | :--- | :--- |
| `liboqs` | `0.16.0` (Pinned CI Reference `5a1a854...`) | Native C implementation of ML-KEM-768 and ML-KEM-1024 |
| `OpenSSL` | `>=3.0` | Native backend for the `cryptography` package |

## 4. Cryptographic Algorithms Used

| Primitive Type | Algorithm | Context |
| :--- | :--- | :--- |
| **Classical KEM** | X25519 | Classical component of hybrid key exchange |
| **Post-Quantum KEM** | ML-KEM-768 / ML-KEM-1024 | Post-quantum components of hybrid key exchange |
| **KDF (Combiner)** | HKDF-SHA384 | Derives symmetric root key from KEM shared secrets |
| **AEAD** | AES-256-GCM | Encrypts and authenticates file payloads and headers |
| **KDF (Keystore)** | Argon2id (default: memory_cost=32768, iterations=3, lanes=1) / Scrypt | Password derivation for at-rest keystore wrapping |
| **PRNG** | `os.urandom()` / `/dev/urandom` | Nonce generation and ephemeral keypair entropy |
