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

Combiner specification
-----------------------
This implementation targets the IND-CCA KEM combiner property described
in draft-ounsworth-cfrg-kem-combiners (IETF CFRG) and follows the
general hybrid key exchange shape used by:
  - RFC 9954 (formerly draft-ietf-tls-hybrid-design)
  - Signal's PQXDH
  - Chrome/BoringSSL hybrid TLS key exchange

The construction concatenates ALL shared secrets as HKDF input key
material and binds ALL ciphertexts, algorithm identifiers, and a
domain-separation context into the HKDF ``info`` parameter using an
unambiguous, length-prefixed canonical encoding.

Encoding rationale (Discussion #2534 feedback)
-----------------------------------------------
The previous implementation used ``b"|".join(...)`` which is AMBIGUOUS:
if any ciphertext or algorithm ID contains the ``|`` byte, field
boundaries are lost and an attacker can move bytes between adjacent
fields.  The new encoding length-prefixes every variable-length field
with a 4-byte big-endian length, making the encoding injective (two
distinct inputs can never produce the same encoded byte string).

We do NOT invent our own combiner math beyond assembling the standard
HKDF construction - the combiner logic here is orchestration around
``cryptography``'s HKDF implementation, not new cryptography.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from .sources import Encapsulation

ROOT_KEY_LEN = 32  # 256-bit output, suitable as an AES-256 key

# Version of the combiner encoding itself.  Bump this (and document the
# migration) if the canonical encoding ever changes again.
COMBINER_SPEC_VERSION: int = 2

# Default context label.  This is the domain-separation string that
# distinguishes cryptoflex's combiner output from any other use of HKDF
# with similar inputs.
DEFAULT_CONTEXT: bytes = b"cryptoflex-hybrid-kem-combiner"


def _encode_info(
    context: bytes,
    components: list[tuple[str, bytes]],
    *,
    spec_version: int = COMBINER_SPEC_VERSION,
) -> bytes:
    """Build the canonical, length-prefixed HKDF ``info`` parameter.

    Encoding (all integers big-endian):
        2 bytes   spec_version          combiner spec version
        4 bytes   len(context)          context label length
        N bytes   context               domain-separation label
        2 bytes   num_components        number of (alg_id, ciphertext) pairs
        for each component:
            4 bytes   len(alg_id_utf8)  algorithm ID length
            N bytes   alg_id_utf8       algorithm ID (UTF-8 encoded)
            4 bytes   len(ciphertext)   ciphertext length
            N bytes   ciphertext        raw ciphertext bytes

    This encoding is injective: two distinct input tuples can never
    produce the same byte string, so the HKDF output is
    cryptographically bound to the exact combination of inputs.
    """
    out = bytearray()

    # domain separation: combiner spec version
    out += struct.pack(">H", spec_version)

    # domain separation: context label (length-prefixed)
    out += struct.pack(">I", len(context))
    out += context

    # number of components
    out += struct.pack(">H", len(components))

    # each component: algorithm ID + ciphertext, both length-prefixed
    for alg_id, ciphertext in components:
        alg_bytes = alg_id.encode("utf-8")
        out += struct.pack(">I", len(alg_bytes))
        out += alg_bytes
        out += struct.pack(">I", len(ciphertext))
        out += ciphertext

    return bytes(out)


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
    context: bytes = DEFAULT_CONTEXT,
) -> CombinedKeyMaterial:
    """Combine multiple (algorithm_id, Encapsulation) pairs into one root key.

    ``encapsulations`` must be non-empty. Order matters for reproducibility
    on the decapsulating side, so callers must pass sources in a fixed,
    agreed order (the SecurityProfile defines this order).
    """
    if not encapsulations:
        raise ValueError("combine() requires at least one encapsulation")

    # IKM = concatenation of all shared secrets
    ikm = b"".join(enc.shared_secret for _, enc in encapsulations)

    # Build canonical info binding context + all algorithm IDs + all ciphertexts
    components = [(alg_id, enc.ciphertext) for alg_id, enc in encapsulations]
    info = _encode_info(context, components)

    hkdf = HKDF(
        algorithm=hashes.SHA384(),
        length=ROOT_KEY_LEN,
        salt=None,
        info=info,
    )
    root_key = hkdf.derive(ikm)

    return CombinedKeyMaterial(root_key=root_key, components=components)


def combine_from_secrets(
    shared_secrets: list[tuple[str, bytes]],
    ciphertexts: list[tuple[str, bytes]],
    *,
    context: bytes = DEFAULT_CONTEXT,
) -> CombinedKeyMaterial:
    """Decapsulation-side equivalent of combine(): rebuild the same root
    key from recovered shared secrets + the ciphertexts that were bound
    during encapsulation. ``shared_secrets`` and ``ciphertexts`` must be in
    the same algorithm order as the original combine() call.
    """
    ids_a = [a for a, _ in shared_secrets]
    ids_b = [a for a, _ in ciphertexts]
    if ids_a != ids_b:
        raise ValueError(
            f"shared_secrets and ciphertexts algorithm order must match: "
            f"{ids_a} != {ids_b}"
        )

    # IKM = concatenation of all shared secrets
    ikm = b"".join(secret for _, secret in shared_secrets)

    # Build canonical info from ciphertexts (same encoding as combine())
    info = _encode_info(context, list(ciphertexts))

    hkdf = HKDF(
        algorithm=hashes.SHA384(),
        length=ROOT_KEY_LEN,
        salt=None,
        info=info,
    )
    root_key = hkdf.derive(ikm)
    return CombinedKeyMaterial(root_key=root_key, components=list(ciphertexts))
