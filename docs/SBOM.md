# Software Bill of Materials (SBOM)

**Project:** `cryptoflex`
**Version:** 0.5.1-dev
**Date:** September 2026

> [!NOTE]
> **Static Reference SBOM**
> This document is a static reference describing the intended dependencies, versions, and cryptographic primitives of the project. It is not an exact, dynamically resolved build SBOM (which would reflect precise, pinned dependency trees of a specific build environment).

## 1. Direct Python Dependencies

| Package | Version Range | Purpose |
| :--- | :--- | :--- |
| `cryptography` | `>=42.0.0,<45.0.0` | AES-256-GCM, X25519 (Classical KEM), HKDF-SHA384, Scrypt |
| `liboqs-python` | `>=0.10.0,<1.0.0` | Python bindings for liboqs (ML-KEM) |

## 2. Underlying Native C Libraries

| Library | Version | Purpose |
| :--- | :--- | :--- |
| `liboqs` | `0.16.0` (Tested Reference) | Native C implementation of ML-KEM-768 and ML-KEM-1024 |
| `OpenSSL` | `>=3.0` | Native backend for the `cryptography` package |

## 3. Cryptographic Algorithms Used

| Primitive Type | Algorithm | Context |
| :--- | :--- | :--- |
| **Classical KEM** | X25519 | Classical component of hybrid key exchange |
| **Post-Quantum KEM** | ML-KEM-768 / ML-KEM-1024 | Post-quantum components of hybrid key exchange |
| **KDF (Combiner)** | HKDF-SHA384 | Derives symmetric root key from KEM shared secrets |
| **AEAD** | AES-256-GCM | Encrypts and authenticates file payloads and headers |
| **KDF (Keystore)** | Argon2id (default: memory_cost=32768, iterations=3, lanes=1) / Scrypt | Password derivation for at-rest keystore wrapping |
| **PRNG** | `os.urandom()` / `/dev/urandom` | Nonce generation and ephemeral keypair entropy |

*Note: This static SBOM is provided for reference. Future reviewed releases will aim to generate these dynamically as part of the artifact build pipeline.*
