# CryptoFlex Combiner Security Analysis

**Status:** informal engineering reasoning, not a formal proof. This document exists to make the design's assumptions and intended properties explicit and reviewable – it is not a substitute for independent cryptographic analysis (see "Independent review" at the end).

## 1. Intended security property

**Intended property:** subject to the assumptions in Section 2, CryptoFlex is designed so that compromise of one bound component secret alone is not intended to reveal the combined root key, provided the other bound component remains secure and its corresponding ciphertext is not attacker‑controlled.

This is phrased as an intent, not a fact: no test in this repository proves this property, and it has not been independently reviewed. It is the design goal `combiner.py` is built to satisfy, following the general shape of concatenation combiners in the literature (Section 4).

## 2. Assumptions this design relies on

- **Independent randomness between sources.** The X25519 exchange and the ML‑KEM exchange in a hybrid profile use independently generated randomness. Nothing in `combiner.py` enforces or verifies this – it is a property of how `ClassicalSource` and `PQCSource` each draw their own randomness.
- **HKDF‑SHA384 extract‑then‑expand security**, as assumed for HKDF (RFC 5869).
- **Fixed‑length shared secrets per algorithm, assumed but not enforced by `combiner.py`.** Length expectations exist at the source level, but `combine()`/`combine_from_secrets()` do not independently verify secret length before concatenation.
- **The ciphertext‑binding property holds as implemented.** The combiner binds every component's ciphertext into the HKDF `info` parameter (see `_encode_info` in `combiner.py`). This binding ensures that an attacker who controls one source's ciphertext cannot mount a mix‑and‑match attack against the other component. The implementation has been reviewed and exercised by `tests/test_adversarial.py`.

## 3. Four‑case informal analysis

**Hybrid profile combining X25519 and ML‑KEM:**

| X25519 | ML‑KEM | Intended security outcome |
|---|---|---|
| Secure | Secure | No leakage beyond what either primitive individually leaks.
| Broken | Secure | Root key should remain unrecoverable because HKDF is assumed to mix the still‑secure ML‑KEM secret with the compromised X25519 secret.
| Secure | Broken | Symmetric to the previous row.
| Broken | Broken | Root key is recoverable – both inputs are known.

## 4. Comparison against established constructions

| | CryptoFlex combiner | RFC 9954 SS3.3 (TLS 1.3 hybrid) | NIST SP 800‑56C Rev. 2 |
|---|---|---|---|
| Core mechanism | Concatenate all shared secrets as HKDF input key material | Concatenation‑based shared‑secret construction | General key‑derivation framework (extraction‑then‑expansion) |
| Secret length handling | Length‑prefixed encoding; **no explicit per‑algorithm length checks** before concatenation (see Section 2) | Specifies fixed‑length component secrets, no extra length fields in wire format | Parameter‑specific length handling is left to the implementing protocol |
| Domain separation | Fixed context string (`cryptoflex‑hybrid‑kem‑combiner`) plus `COMBINER_SPEC_VERSION` field | TLS 1.3 key schedule uses its own labeling | Recommended but not mandated; implementation‑specific |
| Scope | Stand‑alone, non‑TLS construction | Specific to TLS 1.3 handshake | General‑purpose framework, not tied to any protocol |
| Formal proof status | None (Section 1) | Backed by TLS 1.3 security analysis (outside CryptoFlex) | No formal proof for a particular instantiation |

This is a **difference comparison**, not an equivalence claim. CryptoFlex follows the general *shape* of these constructions (concatenate secrets, derive via HKDF, bind context) but is its own project‑specific construction.

## 5. Independent cryptographic review

**Explicitly out of scope for this document and not performed.** A formal security proof of this combiner, and an independent cryptographer's review of the reasoning in Sections 1‑3, are listed as unresolved items in the project's technical review. Nothing in this document should be read as satisfying either of those.
