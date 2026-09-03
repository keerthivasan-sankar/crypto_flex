# cryptoflex

[![tests](https://github.com/keerthivasan-sankar/crypto_flex/actions/workflows/tests.yml/badge.svg)](https://github.com/keerthivasan-sankar/crypto_flex/actions/workflows/tests.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue.svg)](pyproject.toml)
[![Version 0.4.0](https://img.shields.io/badge/version-0.4.0-green.svg)](pyproject.toml)

A **local-first crypto-agility policy engine** for Python.

`cryptoflex` doesn't implement any new cryptography. It orchestrates
existing, audited primitives — classical X25519 and post-quantum ML-KEM
(via [liboqs](https://github.com/open-quantum-safe/liboqs)) — behind a
policy engine that decides which combination an application should use,
based entirely on **local signals**. No network calls, no telemetry, no
third-party service dependency, ever.

---

## What's New in v0.4.0

- 🔒 **High-Level AEAD Encryption & Decryption (`encrypt`/`decrypt`)**: AES-256-GCM authenticated encryption with self-describing header authenticated as Associated Data (AAD).
- ⚡ **Forward-Secret Ephemeral Messaging (`ephemeral_encrypt`/`ephemeral_decrypt`)**: Message-level forward secrecy with automatic ephemeral key generation and disposal.
- 📦 **Chunked Streaming AEAD (`encrypt_stream`/`decrypt_stream`)**: Memory-efficient streaming encryption for multi-gigabyte files with per-chunk sequence binding.
- 🔑 **Password-Wrapped Keystore (`export_keyset_bytes`/`import_keyset_bytes`)**: Secure private key storage encrypted with Scrypt ($N=2^{17}$) + AES-256-GCM.
- 🖥️ **Command-Line Interface (`cryptoflex CLI`)**: Comprehensive CLI for key generation, file encryption/decryption, streaming, and header inspection.
- 🛡️ **Hardened Error Boundaries & Property Fuzzing**: Property-based fuzz testing via `hypothesis` and uniform `DecryptionError` exception boundaries to prevent timing/error side-channel leaks.

---

## Why this exists

Most encryption tools hardcode one algorithm stack and never revisit
that choice. If the underlying math is ever weakened — most notably,
elliptic-curve crypto against a future large-scale quantum computer —
every app built on it needs a rewrite. Large platforms (Signal, Chrome,
Cloudflare) have already shipped hybrid classical+PQC key exchange for
their own protocols. This project targets what they haven't: **local,
offline, file-based tools** — encryption utilities, desktop apps,
embedded/IoT — where there's still no clean, drop-in crypto-agility
layer.

---

## Installation

```bash
pip install cryptoflex          # classical-only, always works
pip install cryptoflex[pqc]     # + PQC support via liboqs-python
```

### Faster PQC install on Debian/Ubuntu:
```bash
sudo apt-get install -y liboqs-dev cmake ninja-build build-essential
pip install cryptoflex[pqc]
```

---

## Quick Start & API Examples

### 1. High-Level File Encryption (AEAD)

```python
from cryptoflex import establish_keys, encrypt, decrypt

# Recipient establishes long-lived keypair
recipient_keys = establish_keys()

# Sender encrypts plaintext using recipient's public bundle
blob = encrypt(recipient_keys.public_bundle, b"Secret document payload")

# Recipient decrypts using their private handles
plaintext = decrypt(recipient_keys.private_handles, blob)
assert plaintext == b"Secret document payload"
```

### 2. Forward-Secret Ephemeral Messaging

```python
from cryptoflex import establish_keys, ephemeral_encrypt, ephemeral_decrypt

# Recipient establishes keys
alice = establish_keys()

# Bob sends an ephemeral message (fresh root key generated & discarded per call)
msg = ephemeral_encrypt(alice.public_bundle, b"Hello Alice, this message is forward-secret!")

# Alice decrypts
decrypted = ephemeral_decrypt(alice.private_handles, msg)
assert decrypted == b"Hello Alice, this message is forward-secret!"
```

### 3. Password-Wrapped Keystore

```python
from cryptoflex import establish_keys, export_keyset_bytes, import_keyset_bytes

keyset = establish_keys()

# Save encrypted private keys to disk
encrypted_keys = export_keyset_bytes(keyset, "MySecretPassphrase123")

# Restore keyset from disk
restored_keyset = import_keyset_bytes(encrypted_keys, "MySecretPassphrase123")
```

### 4. Large File Streaming AEAD

```python
from cryptoflex import establish_keys, encrypt_stream, decrypt_stream

keyset = establish_keys()

# Encrypt 10 GB stream chunk-by-chunk
with open("large_file.iso", "rb") as fin, open("encrypted.cflx", "wb") as fout:
    encrypt_stream(keyset.public_bundle, fin, fout)

# Decrypt stream chunk-by-chunk
with open("encrypted.cflx", "rb") as fin, open("restored.iso", "wb") as fout:
    decrypt_stream(keyset.private_handles, fin, fout)
```

---

## Command-Line Interface (CLI)

`cryptoflex` includes a full-featured CLI:

```bash
# 1. Generate keyset and public bundle (password via prompt or CRYPTOFLEX_PASSWORD env var)
cryptoflex keygen --key secret.cflk --bundle public.json

# 2. Encrypt a file
cryptoflex encrypt --in document.pdf --out document.cflx --bundle public.json

# 3. Decrypt a file
cryptoflex decrypt --in document.cflx --out restored.pdf --key secret.cflk

# 4. Stream-encrypt large files
cryptoflex encrypt --in dataset.tar --out dataset.cflx --bundle public.json --stream

# 5. Inspect header metadata
cryptoflex info document.cflx
```

---

## Security Profiles (v1)

| Profile ID         | Components                  | Quantum-safe | Strength |
|--------------------|-----------------------------|--------------|----------|
| `classical_only`   | X25519                      | No           | 1        |
| `hybrid_standard`  | X25519 + ML-KEM-768         | Yes          | 2        |
| `hybrid_high`      | X25519 + ML-KEM-1024        | Yes          | 3        |

---

## Hardening & Security Guarantees

- **Combiner Security**: Uses HKDF-SHA384 with injective length-prefixed encoding and profile-specific domain separation (`b"cryptoflex-hybrid-kem-combiner-" + profile_id`), following RFC 9954.
- **AEAD Integrity**: Serialized headers are authenticated as AEAD Associated Data (AAD), preventing header tampering.
- **Downgrade Protection**: `decrypt()` enforces `min_profile` limits, raising `DowngradeError` before performing decapsulation.
- **Uniform Error Boundary**: All cryptographic failures collapse into generic `DecryptionError` to eliminate timing/error side-channels.
- **Password Hardening**: Key wrapping uses Scrypt ($N=2^{17}, r=8, p=1$) + AES-256-GCM.

---

## Running Tests

```bash
pip install -e ".[dev]"
CRYPTOFLEX_DISABLE_PQC=1 pytest -v
```

---

## License

MIT License. See [LICENSE](LICENSE) for details.
