# cryptoflex Format & Cryptographic Specification (v0.5.2)

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

The IKM is formed by concatenating the fixed-length component shared secrets:

$$\text{IKM} = S_1 \parallel S_2 \parallel \dots \parallel S_M$$

**Fixed-length component invariant:**
For all currently registered CryptoFlex components, the shared-secret representation is fixed-length for a given algorithm. The combiner therefore uses direct concatenation of component shared secrets. Any future variable-length component must introduce an unambiguous canonical encoding before it can be incorporated into the combiner.

### 2.2 Info Context String (`info`)

To guarantee strict context binding and prevent cross-algorithm substitution, the HKDF `info` parameter is constructed exactly as:

$$\text{info} = \text{uint16\_be}(2) \parallel \text{uint32\_be}(|ctx|) \parallel ctx \parallel \text{uint16\_be}(M) \parallel \bigparallel_{i=1}^M \left( \text{uint32\_be}(|A_i|) \parallel A_i \parallel \text{uint32\_be}(|C_i|) \parallel C_i \right)$$

where:
- $ctx$ is the fixed context label: `"cryptoflex-hybrid-kem-combiner"`
- $M$ is the number of component key encapsulations.
- $A_i$ is the UTF-8 algorithm identifier string for component $i$.
- $C_i$ is the raw ciphertext bytes for component $i$.
- $\text{uint32\_be}$ and $\text{uint16\_be}$ denote 4-byte and 2-byte big-endian integers, respectively.

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

For files exceeding RAM capacity, `encrypt_stream()` processes payloads in sequential authenticated frames.

### Stream Structure Layout

| Sequence Block | Field Name | Type / Length | Description |
| :--- | :--- | :--- | :--- |
| **Preamble** | **Stream Header** | Variable | Full v2 `CryptoflexHeader` (Section 1) containing `BaseNonce` |
| **Frame $i$** | **Frame Type** | 1 byte (`uint8`) | `0x01` = DATA, `0x02` = FINAL |
| | **Ciphertext Length** | 4 bytes (`uint32`, Big-Endian) | Byte length $C$ of AEAD payload (ciphertext + 16B tag) |
| | **AEAD Payload** | $C$ bytes (`bytes`) | AES-256-GCM encrypted ciphertext + 16-byte tag |

### 4.1 Frame Types

**DATA frame** (`0x01`): Carries an encrypted plaintext chunk.
- Plaintext size: `1` to `MAX_CHUNK_PLAINTEXT_SIZE` (9 MB) bytes.
- Ciphertext size: plaintext size + 16 bytes (GCM tag).

**FINAL frame** (`0x02`): Mandatory stream terminator.
- Plaintext: empty (`b""`).
- Ciphertext: exactly 16 bytes (GCM tag over empty plaintext).
- Must be the last frame. Any data after FINAL is rejected.

### 4.2 Sequence Numbering

Frames are numbered sequentially starting from 0:

```
DATA   0
DATA   1
...
DATA   N
FINAL  N+1
```

The sequence counter is bound into both the nonce and AAD of every frame.

### 4.3 Per-Frame Nonce Derivation

For each frame $i$:
$$\text{Nonce}_i = \text{BaseNonce}[0..7] \parallel \text{uint32\_be}(i)$$

### 4.4 Per-Frame AAD Construction

For DATA frames:
$$\text{AAD}_i = \text{HeaderBytes} \parallel \text{uint32\_be}(i) \parallel \text{b"DATA"}$$

For the FINAL frame:
$$\text{AAD}_i = \text{HeaderBytes} \parallel \text{uint32\_be}(i) \parallel \text{b"FINAL"}$$

Binding the frame type tag into the AAD ensures that a DATA frame cannot be reinterpreted as a FINAL frame, and vice versa.

### 4.5 Maximum Frame Size

Maximum plaintext chunk size: 9 MB (`9 * 1024 * 1024` bytes).  
Maximum ciphertext frame size: 9 MB + 16 bytes.  
Default chunk size: 64 KB (`64 * 1024` bytes).

### 4.6 EOF and Stream Integrity

Successful decryption requires receiving and authenticating a FINAL frame. The following are all rejected:
- Missing FINAL frame (stream truncation)
- Forged FINAL frame (wrong GCM tag)
- Wrong sequence number on FINAL frame
- DATA frames after FINAL
- Trailing bytes after FINAL
- Invalid frame type bytes
- Legacy unauthenticated `0x00000000` terminal markers

### 4.7 Legacy Stream Behavior

Streams produced by CryptoFlex versions prior to v0.5.2 used an unauthenticated `0x00000000` 4-byte terminal marker. These streams are **not accepted** by the current decoder. They must be re-encrypted using the current version to gain authenticated stream termination.

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

---

## 6. Hybrid Combiner Specification & Design Rationale

This section provides the mathematical formalization of the `cryptoflex` hybrid KEM combiner $\mathcal{C}(\mathbf{S}, \mathbf{C})$.

**Important Disclaimer:** The construction described below is a project-specific construction intended to combine component secrets using HKDF-SHA384. It currently requires independent cryptographic review, and the design rationale presented does not constitute a formal IND-CCA security proof.

### 6.1 Mathematical Definition

Let $\mathbf{S} = (S_1, S_2, \dots, S_M)$ be a sequence of shared secrets established by component key encapsulation mechanisms $\text{KEM}_1, \dots, \text{KEM}_M$.  
Let $\mathbf{C} = ((A_1, C_1), \dots, (A_M, C_M))$ be the corresponding tuples of algorithm identifiers $A_i$ and KEM ciphertexts $C_i$.

The combiner mapping $\mathcal{C}: (\{0,1\}^*)^M \times (\{0,1\}^* \times \{0,1\}^*)^M \to \{0,1\}^{256}$ is defined as:

$$\text{IKM} = \phi(\mathbf{S}) = \bigparallel_{i=1}^M S_i$$

$$\text{info} = \psi(\mathbf{C}) = \text{uint16\_be}(2) \parallel \text{uint32\_be}(|ctx|) \parallel ctx \parallel \text{uint16\_be}(M) \parallel \bigparallel_{i=1}^M \left( \text{uint32\_be}(|A_i|) \parallel A_i \parallel \text{uint32\_be}(|C_i|) \parallel C_i \right)$$

$$\text{PRK} = \text{HKDF-Extract}(0^{48}, \text{IKM})$$

$$\text{RootKey} = \text{HKDF-Expand}(\text{PRK}, \text{info}, 32)$$

### 6.2 Security Intuition: Dual-KEM Hybrid Design Rationale

> **Design Rationale (Dual-PRF Expectation)**:  
> The design anticipates that if HKDF-Extract acts as a dual pseudorandom function (Dual-PRF) or random oracle, and if **at least one** component mechanism $\text{KEM}_k \in \{\text{KEM}_1, \dots, \text{KEM}_M\}$ is secure, then the derived $\text{RootKey}$ should be indistinguishable from a uniform random 256-bit key.

*Rationale Sketch*:  
If $S_k$ provides sufficient min-entropy given $C_k$, the concatenated string $\text{IKM} = \phi(\mathbf{S})$ should carry that entropy. Under the Dual-PRF property of HKDF-Extract (RFC 5869 / Krawczyk 2010), $\text{HKDF-Extract}(0^{48}, \text{IKM})$ is expected to yield a pseudorandom key $\text{PRK}$. Expanding $\text{PRK}$ with context $\text{info}$ via HKDF-Expand then preserves pseudorandomness for $\text{RootKey}$. Note: this is an expected property, not a formal security proof.

### 6.3 Design Rationale: Injectivity of Pre-fixed Formatting (RFC 9954)

> **Design Rationale (Unambiguous Encoding)**:  
> Current fixed-length shared-secret vectors are unambiguous under direct concatenation.
> Future variable-length secrets require explicit length encoding before incorporation into the combiner.

*Rationale*:  
The info encoding function $\psi(\mathbf{C})$ uses 4-byte big-endian length prefixes for each variable-length field, making it injective (two distinct input tuples cannot produce the same byte string). The IKM encoding $\phi(\mathbf{S})$ relies on the fact that all currently registered CryptoFlex components produce fixed-length shared secrets for a given algorithm, making direct concatenation unambiguous for those components. This should not be interpreted as a general injectivity claim for arbitrary variable-length inputs.

### 6.4 Design Rationale: AEAD Header Binding & Non-Malleability

> **Design Rationale (Header Non-Malleability)**:  
> Let $\text{Payload} = \text{HeaderBytes} \parallel \text{AES-256-GCM-Encrypt}_{K}(\text{Nonce}, \text{Plaintext}, \text{AAD}=\text{HeaderBytes})$.  
> Any modification to $\text{HeaderBytes}$ (including profile string, algorithm list, KEM ciphertexts, or nonce) alters the Associated Data $\text{AAD}$. This relies on the standard INT-CTXT (ciphertext integrity) property of AES-256-GCM to reject modified payloads.

