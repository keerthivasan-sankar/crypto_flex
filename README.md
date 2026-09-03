# cryptoflex

[![tests](https://github.com/keerthivasan-sankar/crypto_flex/actions/workflows/tests.yml/badge.svg)](https://github.com/keerthivasan-sankar/crypto_flex/actions/workflows/tests.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue.svg)](pyproject.toml)
[![Version 0.4.1](https://img.shields.io/badge/version-0.4.1-green.svg)](pyproject.toml)

A local-first crypto-agility policy engine for Python.

`cryptoflex` sits between your application and its cryptographic primitives. It selects the strongest combination of classical (X25519) and post-quantum (ML-KEM via [liboqs](https://github.com/open-quantum-safe/liboqs)) algorithms that the current machine can support, then hands you a single root key — without ever making a network call.

> **Status:** unaudited research prototype. See [`TECHNICAL_REVIEW_1.md`](TECHNICAL_REVIEW_1.md) for a full self-assessment and what that means in practice before using this for anything sensitive.

---

## Motivation

Most encryption tools are frozen to a single algorithm stack. When that stack ages — or when a large-scale quantum computer eventually threatens elliptic-curve math — every system built on it needs a coordinated migration. Signal, Chrome, and Cloudflare have already shipped hybrid classical+PQC key exchange at the protocol level. `cryptoflex` targets the tooling side of that same problem: local, offline applications — desktop utilities, backup tools, embedded devices — that have no equivalent solution today.

---

## Installation

```bash
# Classical-only (no native dependencies)
pip install cryptoflex

# With post-quantum support
pip install cryptoflex[pqc]
```

On Debian/Ubuntu, building `liboqs` from source is faster with:

```bash
sudo apt-get install -y liboqs-dev cmake ninja-build build-essential
pip install cryptoflex[pqc]
```

---

## Usage

### File encryption

```python
from cryptoflex import establish_keys, encrypt, decrypt

# Recipient generates a keypair once and shares the public bundle
recipient = establish_keys()

# Sender encrypts — only the recipient's private key can open this
ciphertext = encrypt(recipient.public_bundle, b"your plaintext here")

# Recipient decrypts
plaintext = decrypt(recipient.private_handles, ciphertext)
```

### Ephemeral messaging (forward secrecy)

Each call to `ephemeral_encrypt` generates a fresh keypair, uses it once, and discards it. Past messages stay safe even if long-term keys are later compromised.

```python
from cryptoflex import establish_keys, ephemeral_encrypt, ephemeral_decrypt

alice = establish_keys()

wire = ephemeral_encrypt(alice.public_bundle, b"hello")
plaintext = ephemeral_decrypt(alice.private_handles, wire)
```

### Keystore — saving keys to disk

Private keys are wrapped with Argon2id + AES-256-GCM before touching disk. Scrypt keystores from earlier versions are still importable.

```python
from cryptoflex import establish_keys, export_keyset_bytes, import_keyset_bytes

keyset = establish_keys()

# Encrypt and save
raw = export_keyset_bytes(keyset, "passphrase")  # Argon2id by default
with open("identity.cflk", "wb") as f:
    f.write(raw)

# Load and decrypt
with open("identity.cflk", "rb") as f:
    keyset = import_keyset_bytes(f.read(), "passphrase")
```

### Streaming large files

For files that do not fit in memory, `encrypt_stream` and `decrypt_stream` process data in 64 KB chunks. Each chunk is independently authenticated and bound to a sequence counter, so truncation and reordering are detected.

```python
from cryptoflex import establish_keys, encrypt_stream, decrypt_stream

keyset = establish_keys()

with open("archive.tar", "rb") as fin, open("archive.tar.cflx", "wb") as fout:
    encrypt_stream(keyset.public_bundle, fin, fout)

with open("archive.tar.cflx", "rb") as fin, open("archive.tar", "wb") as fout:
    decrypt_stream(keyset.private_handles, fin, fout)
```

### Wiping sensitive memory

```python
from cryptoflex import zeroize

buf = bytearray(key_material)
# ... use buf ...
zeroize(buf)  # overwrites in-place with 0x00
```

---

## CLI

```
cryptoflex keygen   --key identity.cflk --bundle identity.json [--kdf argon2id|scrypt]
cryptoflex encrypt  --in plain.dat  --out plain.cflx  --bundle identity.json [--stream]
cryptoflex decrypt  --in plain.cflx --out plain.dat   --key identity.cflk   [--stream]
cryptoflex migrate  --in old.cflx   --out new.cflx    --key identity.cflk --new-bundle new.json
cryptoflex info     file.cflx
```

`keygen` defaults to Argon2id. Pass `--kdf scrypt` to produce a keystore compatible with v0.4.0 and earlier. Passwords are read from the `CRYPTOFLEX_PASSWORD` environment variable, or prompted interactively if neither that nor `--password` is set.

---

## Security profiles

The policy engine picks the strongest profile available at runtime. Profiles are evaluated in descending strength order; if `liboqs` is absent the engine falls back to the classical-only profile rather than failing.

| Profile | Components | Post-quantum |
|---|---|:---:|
| `hybrid_high` | X25519 + ML-KEM-1024 | Yes |
| `hybrid_standard` | X25519 + ML-KEM-768 | Yes |
| `classical_only` | X25519 | No |

To enforce a minimum: `decrypt(handles, blob, min_profile="hybrid_standard")`. This raises `DowngradeError` before any cryptographic operation if the ciphertext was produced under a weaker profile.

---

## Design notes

**Combiner.** The root key is derived via HKDF-SHA384 over all shared secrets and ciphertexts, with injective length-prefixed encoding and a profile-scoped context string. This follows the structure of [RFC 9954](https://www.rfc-editor.org/info/rfc9954) and ensures the hybrid key is no weaker than the strongest component.

**Header integrity.** The full serialized header is passed as Associated Data to AES-256-GCM. Any modification to algorithm identifiers, the nonce, or the ciphertext components causes decryption to fail before the payload is touched.

**Error surface.** All decryption failures — wrong key, corrupted header, tampered ciphertext, authentication failure — surface as a single `DecryptionError`. Callers cannot distinguish between failure modes, which eliminates error side-channels.

**Password hardening.** Keystore wrapping uses Argon2id (m=64 MB, t=3, p=4) by default, or Scrypt (N=2¹⁷, r=8, p=1) for compatibility. The algorithm is stored in the file header so the right KDF is always used on import.

---

## Testing

78 tests covering unit, integration, adversarial, and property-based (Hypothesis) cases.

```bash
pip install -e ".[dev]"

# Without liboqs installed:
CRYPTOFLEX_DISABLE_PQC=1 pytest -v

# End-to-end verification script:
python verify_local.py
```

---

## License

MIT. See [LICENSE](LICENSE).
