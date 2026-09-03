"""
cryptoflex.api
================

High-level entry points most callers should use instead of touching
sources/combiner/policy/header directly.

Recommended API (Discussion #2534 hardening)
----------------------------------------------
    encrypt(bundle, plaintext) -> bytes
    decrypt(private_handles, blob, *, min_profile=None) -> bytes

These perform AES-256-GCM with the full serialized header as AEAD
associated data, so any modification to the version, profile, algorithm
identifiers, ciphertexts, or nonce is detected by the AEAD tag check.

The older derive_root_key() / recover_root_key() remain available for
advanced callers who manage their own symmetric encryption, but the new
encrypt/decrypt functions are the recommended boundary.

Error model (Discussion #2534 feedback)
-----------------------------------------
    "Do not expose distinguishable errors or timing for 'classical
    failed', 'ML-KEM failed', and 'payload authentication failed'.
    Return one generic failure at the API boundary."

Both decrypt() and recover_root_key() catch ALL internal exceptions and
re-raise a single DecryptionError("decryption failed").  Callers never
learn which source or step failed.  DowngradeError (a DecryptionError
subclass) is the one exception: it fires BEFORE any crypto operation
when the header's profile is weaker than the caller's min_profile.
"""

from __future__ import annotations

import os
from dataclasses import dataclass

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .combiner import CombinedKeyMaterial, combine, combine_from_secrets
from .errors import DecryptionError, DowngradeError
from .header import NONCE_LEN, CryptoflexHeader, HeaderParseError
from .policy import Constraint, PolicyDecision, PolicyEngine
from .profiles import SecurityProfile, get_profile


@dataclass
class PublicBundle:
    profile_id: str
    public_keys: list[tuple[str, bytes]]  # (algorithm_id, public_key_bytes)


@dataclass
class KeySet:
    profile: SecurityProfile
    public_bundle: PublicBundle
    #: opaque per-source private key handles, in the SAME order as
    #: profile.sources - needed later to decapsulate
    private_handles: list[object]
    policy_decision: PolicyDecision


@dataclass
class DerivedRoot:
    root_key: bytes
    header: CryptoflexHeader


# ---------------------------------------------------------------------------
# Key establishment (unchanged from v0.1)
# ---------------------------------------------------------------------------

def establish_keys(
    engine: PolicyEngine | None = None,
    constraint: Constraint = Constraint.BALANCED,
    *,
    require_quantum_safe: bool = False,
) -> KeySet:
    """Generate a fresh keypair for every source in the policy-selected
    profile.  Call this once per identity/session; keep private_handles
    secret."""
    engine = engine or PolicyEngine()
    decision = engine.decide(constraint, require_quantum_safe=require_quantum_safe)
    profile = decision.profile

    public_keys: list[tuple[str, bytes]] = []
    private_handles: list[object] = []
    for source in profile.sources:
        pub, priv = source.generate_keypair()
        public_keys.append((source.algorithm_id, pub))
        private_handles.append(priv)

    bundle = PublicBundle(profile_id=profile.profile_id, public_keys=public_keys)
    return KeySet(
        profile=profile,
        public_bundle=bundle,
        private_handles=private_handles,
        policy_decision=decision,
    )


# ---------------------------------------------------------------------------
# Low-level key derivation (preserved for advanced callers)
# ---------------------------------------------------------------------------

def derive_root_key(bundle: PublicBundle) -> DerivedRoot:
    """Given someone else's PublicBundle, derive a fresh root key and
    produce the header to send/store alongside your ciphertext.

    NOTE: This is the low-level API.  Prefer encrypt() which handles
    AEAD and header authentication automatically.
    """
    profile = get_profile(bundle.profile_id)
    if len(profile.sources) != len(bundle.public_keys):
        raise ValueError(
            f"public bundle has {len(bundle.public_keys)} keys but profile "
            f"'{bundle.profile_id}' expects {len(profile.sources)}"
        )

    encapsulations = []
    for source, (alg_id, pub_key) in zip(profile.sources, bundle.public_keys):
        if source.algorithm_id != alg_id:
            raise ValueError(
                f"public bundle component order mismatch: expected "
                f"'{source.algorithm_id}', got '{alg_id}'"
            )
        enc = source.encapsulate(pub_key)
        encapsulations.append((alg_id, enc))

    combined: CombinedKeyMaterial = combine(encapsulations)

    # Generate nonce for v2 header
    nonce = os.urandom(NONCE_LEN)

    header = CryptoflexHeader(
        profile_id=bundle.profile_id,
        components=combined.components,
        nonce=nonce,
    )
    return DerivedRoot(root_key=combined.root_key, header=header)


def recover_root_key(
    private_handles: list[object],
    header: CryptoflexHeader,
    *,
    min_profile: str | None = None,
) -> bytes:
    """Given the private handles from establish_keys() and a received
    header, recover the same root key derive_root_key() produced.

    If ``min_profile`` is specified, the header's profile must have a
    strength_level >= the min_profile's strength_level, or DowngradeError
    is raised BEFORE any cryptographic operation.

    All cryptographic failures are collapsed into DecryptionError.
    """
    # --- downgrade check (before any crypto) ---
    try:
        header_profile = get_profile(header.profile_id)
    except ValueError:
        raise DecryptionError("decryption failed")

    if min_profile is not None:
        try:
            min_prof = get_profile(min_profile)
        except ValueError:
            raise DecryptionError("decryption failed")
        if header_profile.strength_level < min_prof.strength_level:
            raise DowngradeError(
                f"header profile '{header.profile_id}' "
                f"(strength={header_profile.strength_level}) is weaker than "
                f"minimum accepted profile '{min_profile}' "
                f"(strength={min_prof.strength_level})"
            )

    # --- uniform error boundary: all crypto failures → DecryptionError ---
    try:
        return _recover_root_key_internal(private_handles, header, header_profile)
    except DecryptionError:
        raise
    except Exception:
        raise DecryptionError("decryption failed")


def _recover_root_key_internal(
    private_handles: list[object],
    header: CryptoflexHeader,
    profile: SecurityProfile,
) -> bytes:
    """Internal implementation of key recovery.  NOT exposed to callers -
    exceptions from here are caught and converted to DecryptionError by
    recover_root_key()."""
    if not (len(profile.sources) == len(private_handles) == len(header.components)):
        raise ValueError(
            "mismatched component counts between profile/handles/header "
            f"(profile expects {len(profile.sources)}, got "
            f"{len(private_handles)} private handles and "
            f"{len(header.components)} header components) - refusing to "
            "silently derive a key from a subset of sources"
        )

    shared_secrets: list[tuple[str, bytes]] = []
    for source, priv_handle, (alg_id, ciphertext) in zip(
        profile.sources, private_handles, header.components
    ):
        if source.algorithm_id != alg_id:
            raise ValueError(
                f"header component order mismatch: expected "
                f"'{source.algorithm_id}', got '{alg_id}'"
            )
        secret = source.decapsulate(priv_handle, ciphertext)
        shared_secrets.append((alg_id, secret))

    combined = combine_from_secrets(shared_secrets, header.components)
    root_key = combined.root_key

    # Eagerly drop intermediate secret references.
    del combined, shared_secrets

    return root_key


# ---------------------------------------------------------------------------
# High-level AEAD encrypt / decrypt (recommended API)
# ---------------------------------------------------------------------------

def encrypt(bundle: PublicBundle, plaintext: bytes) -> bytes:
    """Derive a root key from the recipient's PublicBundle and encrypt
    ``plaintext`` under AES-256-GCM with the full serialized header as
    AEAD associated data.

    Returns a self-contained blob:
        header_bytes || AES-GCM(ciphertext || 16-byte tag)

    The header contains: magic, version, profile ID, all KEM ciphertexts,
    and the AES-GCM nonce.  All of these fields are authenticated by the
    AEAD tag, so any modification to them causes decryption to fail.
    """
    derived = derive_root_key(bundle)

    header_bytes = derived.header.to_bytes()
    nonce = derived.header.nonce
    if nonce is None:  # v2 headers always have a nonce
        raise ValueError("derive_root_key() produced a v1 header with no nonce — cannot encrypt")

    aesgcm = AESGCM(derived.root_key)
    ct_with_tag = aesgcm.encrypt(nonce, plaintext, header_bytes)

    # Eagerly drop root key reference to reduce its heap lifetime.
    del aesgcm, derived

    return header_bytes + ct_with_tag


def decrypt(
    private_handles: list[object],
    blob: bytes,
    *,
    min_profile: str | None = None,
) -> bytes:
    """Parse the header from ``blob``, recover the root key, and decrypt
    the AEAD payload.

    If ``min_profile`` is specified, the header's profile must have a
    strength_level >= the min_profile's strength_level, or DowngradeError
    is raised BEFORE any cryptographic operation.

    All other failures (wrong keys, tampered header, tampered ciphertext,
    truncated data, etc.) are collapsed into a single DecryptionError
    with no indication of which step failed.
    """
    # --- parse header ---
    try:
        header, consumed = CryptoflexHeader.from_bytes(blob)
    except HeaderParseError:
        raise DecryptionError("decryption failed")

    # --- downgrade check (before any crypto) ---
    if min_profile is not None:
        try:
            header_profile = get_profile(header.profile_id)
            min_prof = get_profile(min_profile)
        except ValueError:
            raise DecryptionError("decryption failed")
        if header_profile.strength_level < min_prof.strength_level:
            raise DowngradeError(
                f"header profile '{header.profile_id}' "
                f"(strength={header_profile.strength_level}) is weaker than "
                f"minimum accepted profile '{min_profile}' "
                f"(strength={min_prof.strength_level})"
            )

    # --- require v2 header for AEAD ---
    if header.nonce is None:
        raise DecryptionError("decryption failed")

    # --- uniform error boundary ---
    try:
        profile = get_profile(header.profile_id)
        raw_root_key = _recover_root_key_internal(private_handles, header, profile)

        header_bytes = blob[:consumed]
        aead_payload = blob[consumed:]

        # Convert to bytearray for in-place zeroization upon return
        root_key_buf = bytearray(raw_root_key)
        del raw_root_key

        try:
            aesgcm = AESGCM(bytes(root_key_buf))
            plaintext = aesgcm.decrypt(header.nonce, aead_payload, header_bytes)
            del aesgcm
            return plaintext
        finally:
            from .utils import zeroize
            zeroize(root_key_buf)
    except (DowngradeError, DecryptionError):
        raise
    except Exception:
        raise DecryptionError("decryption failed")
