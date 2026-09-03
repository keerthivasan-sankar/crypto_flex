# cryptoflex Format & Cryptographic Specification (v0.4.1)

This document provides a formal technical specification of the data formats, key derivation mechanisms, and framing rules implemented by `cryptoflex`.

---

## 1. Serialized Header Wire Format (v2)

All integers are encoded in **big-endian (network) byte order**.

```text
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                       Magic: "CFLX"                           |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
| Version (0x02)| ProfileLen(N) | Profile ID (N bytes UTF-8)... |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
| NumComp (M)   | AlgIDLen_1    | Alg ID 1 (UTF-8)...           |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|      CiphertextLength_1 (uint16)      | Ciphertext 1...       |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
| ... [repeat for component 2..M] ...                           |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                    AES-256-GCM Nonce (12 bytes)               |
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

### Field Definitions

1. **Magic (4 bytes)**: `0x43 0x46 0x4C 0x58` (`"CFLX"` in ASCII).
2. **Version (1 byte)**: `0x02` (v2 wire format).
3. **Profile ID Length (1 byte)**: Length `N` of the profile identifier.
4. **Profile ID (`N` bytes)**: UTF-8 string identifying the policy profile (e.g. `hybrid_standard`, `hybrid_high`, `classical_only`).
5. **Number of Components (1 byte)**: Count `M` of key encapsulation components in the profile.
6. **Component Entries (`M` items)**:
   - **Algorithm ID Length (1 byte)**: Length of the component algorithm identifier.
   - **Algorithm ID (Variable)**: UTF-8 string (e.g. `x25519`, `mlkem768`, `mlkem1024`).
   - **Ciphertext Length (2 bytes, uint16)**: Length `L` of the encapsulated ciphertext.
   - **Ciphertext (`L` bytes)**: The raw public key or KEM ciphertext for this component.
7. **Nonce (12 bytes)**: Cryptographically secure random nonce (`os.urandom(12)`) used for the AEAD payload.

---

## 2. Hybrid Key Combiner (HKDF-SHA384)

The hybrid root key is derived using **HKDF-SHA384** (RFC 5869) over all component shared secrets and ciphertexts, following the injectivity requirements of RFC 9954.

### 2.1 Input Keying Material (IKM)

The IKM is formed by concatenating all 2-byte length-prefixed component shared secrets:

$$\text{IKM} = \text{len}(S_1) \parallel S_1 \parallel \text{len}(S_2) \parallel S_2 \parallel \dots \parallel \text{len}(S_M) \parallel S_M$$

where $\text{len}(S_i)$ is a 2-byte big-endian integer representing the byte length of shared secret $S_i$.

### 2.2 Info Context String (`info`)

To guarantee strict context binding and prevent cross-algorithm substitution, the HKDF `info` parameter is constructed as:

$$\text{info} = \text{"cryptoflex-combiner-v1"} \parallel \text{len}(A_1) \parallel A_1 \parallel \text{len}(C_1) \parallel C_1 \parallel \dots \parallel \text{len}(A_M) \parallel A_M \parallel \text{len}(C_M) \parallel C_M$$

where:
- $A_i$ is the UTF-8 algorithm identifier string.
- $C_i$ is the raw ciphertext bytes for component $i$.
- $\text{len}(A_i)$ is a 1-byte big-endian length prefix.
- $\text{len}(C_i)$ is a 2-byte big-endian length prefix.

### 2.3 Key Extraction & Expansion

1. **Extract**:
   $$\text{PRK} = \text{HKDF-Extract}(\text{salt}=\text{NULL}, \text{IKM})$$
2. **Expand**:
   $$\text{RootKey} = \text{HKDF-Expand}(\text{PRK}, \text{info}, L=32)$$

The derived $\text{RootKey}$ is a 256-bit (32-byte) symmetric key used for AES-256-GCM.

---

## 3. AEAD File & Blob Encryption

High-level `encrypt()` produces a single self-contained byte payload:

$$\text{Payload} = \text{HeaderBytes} \parallel \text{AES-256-GCM-Encrypt}_{K}(\text{Nonce}, \text{Plaintext}, \text{AAD}=\text{HeaderBytes})$$

where:
- $K = \text{RootKey}$ (32 bytes).
- $\text{Nonce}$ is the 12-byte random nonce embedded in the header.
- $\text{HeaderBytes}$ is the full serialized header (Section 1). Passing $\text{HeaderBytes}$ as Associated Data (AAD) ensures any tampering with the version, profile ID, component algorithms, ciphertexts, or nonce causes tag verification failure **before** plaintext is exposed.
- $\text{Tag}$ is the standard 16-byte GCM authentication tag appended to the ciphertext.

---

## 4. Streaming Framing Specification

For files exceeding RAM capacity, `encrypt_stream()` writes a chunked stream format:

```text
+-----------------------+-----------------------+-----------------------+-----
| HeaderBytes (v2)      | Chunk 1 Length (4B)   | Chunk 1 AEAD Payload  | ...
+-----------------------+-----------------------+-----------------------+-----
```

### 4.1 Per-Chunk Framing

For each chunk $i$ ($i = 0, 1, 2, \dots$):
1. **Chunk Length (4 bytes, uint32)**: Big-endian length of the chunk AEAD payload (ciphertext + 16-byte tag). Default chunk size is 64 KB (65,536 bytes of plaintext).
2. **Per-Chunk Nonce (12 bytes)**:
   $$\text{Nonce}_i = \text{BaseNonce}[0..7] \parallel \text{uint32\_be}(i)$$
   where $\text{BaseNonce}$ is the 12-byte nonce embedded in the stream header.
3. **Per-Chunk AAD**:
   $$\text{AAD}_i = \text{HeaderBytes} \parallel \text{uint32\_be}(i)$$
   Binding the sequence counter $i$ into both the nonce and AAD guarantees that chunk reordering, deletion, insertion, or swapping between streams is detected.

### 4.2 Stream Termination

Clean stream end is indicated by a **Terminal Marker**:
- **Terminal Length (4 bytes)**: `0x00 0x00 0x00 0x00` (length 0).
Truncated streams missing the terminal marker fail verification.

---

## 5. Keystore Format (`.cflk` / `.cfla`)

Encrypted KeySets exported via `export_keyset_bytes()` use password-based key derivation:

```text
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                     Magic: "CFLA" or "CFLK"                   |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                     Salt (16 bytes)                           |
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                     AES-256-GCM Nonce (12 bytes)               |
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                     AES-256-GCM Payload + 16B Tag             |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

### Magic Identifiers
- `"CFLA"`: **Argon2id** KDF (default). Parameters: $m=32\,\text{MB}$, $t=3$, $p=1$, salt=16 bytes, key length=32 bytes.
- `"CFLK"`: **Scrypt** KDF (legacy). Parameters: $N=2^{17}$, $r=8$, $p=1$, salt=16 bytes, key length=32 bytes.

The decrypted JSON payload contains the `profile_id`, the recipient `PublicBundle`, and base64-encoded serialized private key handles.
