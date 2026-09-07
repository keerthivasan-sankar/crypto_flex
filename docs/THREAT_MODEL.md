# cryptoflex Threat Model & Security Analysis (v0.5.0)

This document formalizes the security goals, attacker models, cryptographic invariants, and known operational limitations of `cryptoflex`.

---

## 1. Primary Security Goals & Invariants

1. **Hybrid Combiner Design Goal**:

   - The construction is intended to derive a root key from both component secrets so that compromise of one component does not by itself expose the other component's contribution. This is a design goal, not a formally proven security guarantee.

   - The following describe intended threat scenarios, not a proof that the combined construction retains the security of either component.

   - In the intended threat scenario, a sufficiently capable quantum computer breaks X25519, while ML-KEM is intended to provide the post-quantum component.

   - Conversely, if ML-KEM were compromised, X25519 is intended to provide the classical component.

2. **Payload & Header Authenticated Encryption**:

   - The entire serialized header (version, profile ID, algorithm identifiers, KEM ciphertexts, AEAD nonce) is authenticated via AES-256-GCM Associated Data (AAD).

   - Any active tampering with algorithm tags or headers causes decryption rejection before payload processing.

3. **Forward Secrecy for Messaging**:

   - **Per-message ephemeral encryption:** `ephemeral_encrypt()` generates fresh sender-side ephemeral key material for each message. However, archived messages remain recoverable if the recipient's long-term private key is later compromised. Therefore, the current implementation does not provide full forward secrecy against compromise of the recipient's long-term private key.

4. **Uniform Failure Surface (No Error Oracles)**:

   - All cryptographic failure paths (invalid key, malformed header, tampered ciphertext, bad AEAD tag) collapse into a uniform `DecryptionError`.

   - Decapsulation handling normalizes externally visible failures. CryptoFlex does not claim constant-time behavior or complete timing-side-channel resistance at the Python layer.

5. **Local Machine Compromise**:

   - If an attacker has `root` / administrator access to the machine while `cryptoflex` is running, they may be able to read process memory directly through OS debugging or memory-access interfaces.

6. **Public key / bundle authenticity**:

   - CryptoFlex does not currently authenticate the identity associated with a `PublicBundle`. An application that receives a bundle must obtain and authenticate it using an external trusted distribution mechanism. An attacker capable of substituting a recipient's public bundle may redirect encryption to attacker-controlled keys.

---

## 2. Attacker Models

### 2.1 Harvest-Now-Decrypt-Later (HNDL) Adversary
* **Capabilities**: Passive network monitor or storage archivist capturing encrypted files/messages today. The adversary possesses (or will possess in 10-30 years) a Cryptographically Relevant Quantum Computer (CRQC).
* **Mitigation**: The hybrid profiles combine X25519 with ML-KEM. The design goal is to retain security from an uncompromised component if another component is broken; this property has not been independently proven for the CryptoFlex-specific construction.

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
2. **Side-Channel Resistance Limitations**:
   - `cryptoflex` wraps underlying C libraries. It does not provide constant-time execution at the Python layer, and any microarchitectural side-channels in the underlying C/Assembly implementations are out of scope.
3. **Local Machine Compromise**:
   - If an attacker has `root` / administrator access to the machine while `cryptoflex` is running, they can read memory directly via `/proc/self/mem` or OS debugging interfaces.
