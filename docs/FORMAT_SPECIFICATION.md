# cryptoflex Format & Cryptographic Specification (v0.4.1)

This document provides a formal technical specification of the data formats, key derivation mechanisms, and framing rules implemented by `cryptoflex`.

---

## 1. Serialized Header Wire Format (v2)

All multi-byte integers are encoded in **big-endian (network) byte order**.

### Header Layout

| Offset (Bytes) | Field Name | Type / Length | Description |
| :---: | :--- | :--- | :--- |
| `0..3` | **Magic** | 4 bytes (`bytes`) | Fixed magic signature: ASCII `"CFLX"` (`0x43 0x46 0x4C 0x58`) |
| `4` | **Version** | 1 byte (`uint8`) | Wire format version number: `0x02` |
| `5` | **Profile Length** | 1 byte (`uint8`) | Byte length $N$ of the profile identifier string |
| `6 .. 5+N` | **Profile ID** | $N$ bytes (`UTF-8`) | Policy profile string (e.g., `hybrid_standard`, `hybrid_high`, `classical_only`) |
| `6+N` | **Component Count** | 1 byte (`uint8`) | Number of component key encapsulations $M$ in the header |
| *Variable* | **Component Entries** | $M$ elements | Array of key encapsulation entries (see sub-table below) |
| *Header End - 12* | **AES-256-GCM Nonce** | 12 bytes (`bytes`) | Random AEAD nonce generated via `os.urandom(12)` |

### Component Entry Layout (Repeated $M$ times)

| Field Name | Type / Length | Description |
| :--- | :--- | :--- |
| **Algorithm ID Length** | 1 byte (`uint8`) | Byte length $A$ of the component algorithm identifier |
| **Algorithm ID** | $A$ bytes (`UTF-8`) | Primitive identifier (e.g., `x25519`, `mlkem768`, `mlkem1024`) |
| **Ciphertext Length** | 2 bytes (`uint16`, Big-Endian) | Byte length $L$ of the component ciphertext |
| **Ciphertext** | $L$ bytes (`bytes`) | Public key or KEM ciphertext for this component |

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

For files exceeding RAM capacity, `encrypt_stream()` processes payloads in sequential chunks.

### Stream Structure Layout

| Sequence Block | Field Name | Type / Length | Description |
| :--- | :--- | :--- | :--- |
| **Preamble** | **Stream Header** | Variable | Full v2 `CryptoflexHeader` (Section 1) containing `BaseNonce` |
| **Chunk $i$ ($i = 0, 1, \dots$)** | **Chunk Payload Length** | 4 bytes (`uint32`, Big-Endian) | Byte length $C$ of chunk AEAD payload (ciphertext + 16B tag) |
| | **AEAD Payload** | $C$ bytes (`bytes`) | AES-256-GCM encrypted chunk ciphertext + 16-byte tag |
| **Terminal Marker** | **Stream End Indicator** | 4 bytes (`uint32`) | `0x00000000` (length 0 signals clean end-of-stream) |

### 4.1 Per-Chunk Framing Logic

For each chunk $i$:
1. **Chunk Payload Length (4 bytes, uint32)**: Big-endian integer. Default chunk size is 64 KB (65,536 bytes of plaintext).
2. **Per-Chunk Nonce (12 bytes)**:
   $$\text{Nonce}_i = \text{BaseNonce}[0..7] \parallel \text{uint32\_be}(i)$$
3. **Per-Chunk AAD**:
   $$\text{AAD}_i = \text{HeaderBytes} \parallel \text{uint32\_be}(i)$$

Binding the sequence counter $i$ into both the nonce and AAD guarantees that chunk reordering, deletion, insertion, or swapping across streams is detected.

---

## 5. Keystore Format (`.cflk` / `.cfla`)

Encrypted KeySets exported via `export_keyset_bytes()` use password-based key derivation.

### Keystore Wire Layout

| Offset (Bytes) | Field Name | Type / Length | Description |
| :---: | :--- | :--- | :--- |
| `0..3` | **Keystore Magic** | 4 bytes (`bytes`) | `"CFLA"` for Argon2id KDF, `"CFLK"` for Scrypt KDF |
| `4..19` | **Salt** | 16 bytes (`bytes`) | Cryptographically random KDF salt |
| `20..31` | **AES-256-GCM Nonce** | 12 bytes (`bytes`) | Random AEAD nonce for keystore payload |
| `32 .. End` | **Encrypted KeySet Payload** | Variable (`bytes`) | AES-256-GCM ciphertext + 16-byte authentication tag |

### KDF Parameters

| Magic | Algorithm | Memory ($m$) | Iterations ($t$) | Parallelism ($p$) | Key Length | Salt Length |
| :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| `"CFLA"` | **Argon2id** (Default) | 32 MB (`32768`) | 3 | 1 lane | 32 bytes | 16 bytes |
| `"CFLK"` | **Scrypt** (Legacy) | $N=2^{17}$ | $r=8$ | $p=1$ | 32 bytes | 16 bytes |

The decrypted JSON payload contains the `profile_id`, the recipient `PublicBundle`, and base64-encoded serialized private key handles.
