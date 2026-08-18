"""
cryptoflex.combiner
=====================

Combines shared secrets from one or more SecuritySource encapsulations
into a single root key.

Security property (informal)
------------------------------
The combined key must be at least as secure as the STRONGEST input
source: an attacker who fully breaks every source except one still
cannot recover the combined key, provided that one unbroken source's
secret and ciphertext are bound into the derivation.

This is the standard "hybrid KEM combiner" property described in
IETF draft-ietf-tls-hybrid-design and used by Signal's PQXDH and
Chrome's hybrid TLS key exchange. The construction below follows the
same shape: concatenate ALL shared secrets AND ALL ciphertexts (and a
context label) as HKDF input key material, then derive the output key.

Binding the ciphertexts (not just the secrets) into the HKDF input
matters: it prevents an attacker who can influence one source's
ciphertext from being able to mount a "confusion" attack across
sources. This detail is easy to get wrong if you just concatenate
secrets and hash them - don't do that; use HKDF with everything bound
in, as below.

We do NOT invent our own combiner math beyond assembling the standard
HKDF construction - the combiner logic here is orchestration around
`cryptography`'s HKDF implementation, not new cryptography.
"""

from __future__ import annotations

from dataclasses import dataclass

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from .sources import Encapsulation

ROOT_KEY_LEN = 32  # 256-bit output, suitable as an AES-256 key


@dataclass(frozen=True)
class CombinedKeyMaterial:
    root_key: bytes
    # the ordered list of (algorithm_id, ciphertext) pairs that were bound
    # into this key - stored so a decapsulating party can verify it used
    # the same inputs, and so this can be serialized into a file header
    components: list[tuple[str, bytes]]


def combine(
    encapsulations: list[tuple[str, Encapsulation]],
    *,
    context: bytes = b"cryptoflex-v1",
) -> CombinedKeyMaterial:
    """Combine multiple (algorithm_id, Encapsulation) pairs into one root key.

    `encapsulations` must be non-empty. Order matters for reproducibility
    on the decapsulating side, so callers must pass sources in a fixed,
    agreed order (the SecurityProfile defines this order).
    """
    if not encapsulations:
        raise ValueError("combine() requires at least one encapsulation")

    ikm = b"".join(enc.shared_secret for _, enc in encapsulations)
    # bind every ciphertext + algorithm id into the HKDF "info" parameter
    # so the derived key is cryptographically tied to exactly these inputs
    info_parts = [context]
    for alg_id, enc in encapsulations:
        info_parts.append(alg_id.encode("utf-8"))
        info_parts.append(enc.ciphertext)
    info = b"|".join(info_parts)

    hkdf = HKDF(
        algorithm=hashes.SHA384(),
        length=ROOT_KEY_LEN,
        salt=None,
        info=info,
    )
    root_key = hkdf.derive(ikm)

    components = [(alg_id, enc.ciphertext) for alg_id, enc in encapsulations]
    return CombinedKeyMaterial(root_key=root_key, components=components)


def combine_from_secrets(
    shared_secrets: list[tuple[str, bytes]],
    ciphertexts: list[tuple[str, bytes]],
    *,
    context: bytes = b"cryptoflex-v1",
) -> CombinedKeyMaterial:
    """Decapsulation-side equivalent of combine(): rebuild the same root
    key from recovered shared secrets + the ciphertexts that were bound
    during encapsulation. `shared_secrets` and `ciphertexts` must be in
    the same algorithm order as the original combine() call.
    """
    ids_a = [a for a, _ in shared_secrets]
    ids_b = [a for a, _ in ciphertexts]
    if ids_a != ids_b:
        raise ValueError(
            f"shared_secrets and ciphertexts algorithm order must match: "
            f"{ids_a} != {ids_b}"
        )

    ikm = b"".join(secret for _, secret in shared_secrets)
    info_parts = [context]
    for alg_id, ct in ciphertexts:
        info_parts.append(alg_id.encode("utf-8"))
        info_parts.append(ct)
    info = b"|".join(info_parts)

    hkdf = HKDF(
        algorithm=hashes.SHA384(),
        length=ROOT_KEY_LEN,
        salt=None,
        info=info,
    )
    root_key = hkdf.derive(ikm)
    return CombinedKeyMaterial(root_key=root_key, components=list(ciphertexts))
