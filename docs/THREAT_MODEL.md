# cryptoflex Threat Model & Security Analysis (v0.4.1)

This document formalizes the security goals, attacker models, cryptographic invariants, and known operational limitations of `cryptoflex`.

---

## 1. Primary Security Goals & Invariants

1. **"At-Least-As-Strong-As-The-Strongest-Component" Security**:
   - If either X25519 or ML-KEM remains unbroken by an attacker, the derived hybrid root key is secure.
   - Shor's algorithm on a quantum computer breaks X25519, but ML-KEM holds.
   - An unforeseen mathematical breakdown in lattice math breaks ML-KEM, but X25519 holds.
2. **Payload & Header Authenticated Encryption**:
   - The entire serialized header (version, profile ID, algorithm identifiers, KEM ciphertexts, AEAD nonce) is authenticated via AES-256-GCM Associated Data (AAD).
   - Any active tampering with algorithm tags or headers causes immediate decryption rejection prior to payload processing.
3. **Forward Secrecy for Messaging**:
   - `ephemeral_encrypt()` produces short-lived KEM ciphertexts per message. Compromising long-term keys later does not decrypt past ephemeral transcripts.
4. **Uniform Failure Surface (No Error Oracles)**:
   - All cryptographic failure paths (invalid key, malformed header, tampered ciphertext, bad AEAD tag) collapse into a uniform `DecryptionError`.
   - `PQCSource.decapsulate()` uses implicit rejection to prevent length-based timing side-channels.

---

## 2. Attacker Models

### 2.1 Harvest-Now-Decrypt-Later (HNDL) Adversary
* **Capabilities**: Passive network monitor or storage archivist capturing encrypted files/messages today. The adversary possesses (or will possess in 10-30 years) a Cryptographically Relevant Quantum Computer (CRQC).
* **Mitigation**: `hybrid_standard` and `hybrid_high` profiles embed NIST FIPS 203 (ML-KEM) alongside X25519. The HKDF-SHA384 combiner extracts entropy from both, ensuring the ciphertext cannot be decrypted even if classical ECC is broken.

### 2.2 Active Man-in-the-Middle (MitM) / File Tampering Adversary
* **Capabilities**: Can modify encrypted blobs in transit or on disk, flip bits in headers, duplicate/reorder stream chunks, or downgrade requested algorithm profiles.
* **Mitigation**:
  - **Header Integrity**: AEAD Associated Data (AAD) authentication.
  - **Stream Protection**: 4-byte sequence counters bound into both nonces and AAD per 64 KB chunk.
  - **Downgrade Protection**: `min_profile` check executed before cryptographic operations.

### 2.3 Local Machine / Memory Scraping Adversary
* **Capabilities**: Has local unprivileged access on the recipient host and attempts to extract raw private keys or symmetric root keys from process memory or swap space.
* **Mitigation**:
  - `zeroize()` uses `ctypes.memset` over mutable buffers (`bytearray`/`memoryview`) to prevent Python compiler/interpreter optimizations from omitting memory wipes.
  - Intermediate key material is eagerly deleted (`del`) to minimize heap lifetime.
* **Limitations**: See Section 3.

---

## 3. Known Operational Limitations & Out-of-Scope Risks

1. **Python Heap Management & Garbage Collection**:
   - In C Python, immutable `bytes` objects cannot be zeroized in-place natively without unsafe interpreter hacks. While `del` is invoked eagerly, actual memory release depends on Python's garbage collector.
   - Operating system swap file locking (`mlock`) is not yet enforced at the Python level.
2. **Native Side-Channel Resistance**:
   - `cryptoflex` relies on `liboqs` (C library) for constant-time ML-KEM execution and Python's standard `cryptography` package for X25519/AES-GCM. Any microarchitectural side-channels in the underlying C/Assembly implementations are out of scope for this policy layer.
3. **Local Machine Compromise**:
   - If an attacker has `root` / administrator access to the machine while `cryptoflex` is running, they can read memory directly via `/proc/self/mem` or OS debugging interfaces.
