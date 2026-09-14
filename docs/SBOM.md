# Software Bill of Materials (SBOM)

**Project:** `cryptoflex`
**Version:** 0.5.2
**Date:** September 2026

> [!NOTE]
> **SBOM Generation & Reference Document**
> This document describes the dependency structure and cryptographic primitives of `cryptoflex`. An automated CycloneDX 1.4 JSON SBOM (`dist/SBOM.json`) is generated during release CI builds using `cyclonedx-bom==4.1.2`, hashed in `dist/SHA256SUMS.txt`, and published alongside release artifacts.

## 1. Scope & Distribution Boundary

* **Included in CI SBOM (`dist/SBOM.json`):** Python build environment dependencies present during artifact generation (`pip`, `build`, `setuptools`, `wheel`, `cyclonedx-bom`).
* **Excluded from Python Package / Release SBOM:** Optional or external dependencies not installed in the build runner environment (such as `liboqs-python` and native `liboqs` C shared objects). Native `liboqs` is an external deployment requirement. In CI, real PQC verification (`tests.yml`) builds native `liboqs` pinned to tag `0.16.0` (commit `5a1a854b0dc9f2141bdc771c555ee60c37950183`).

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
