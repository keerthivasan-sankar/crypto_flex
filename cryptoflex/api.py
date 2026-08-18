"""
cryptoflex.api
================

High-level entry points most callers should use instead of touching
sources/combiner/policy/header directly.

Typical flow for the party generating a keypair (e.g. "recipient" or
"vault owner"):

    engine = PolicyEngine()
    keyset = establish_keys(engine, constraint=Constraint.BALANCED)
    # keyset.public_bundle: send/store this (public keys per source)
    # keyset.private_handles: keep secret, needed to decapsulate later

Typical flow for the party deriving the root key (e.g. "sender" or
"encrypt this file right now"):

    result = derive_root_key(keyset.public_bundle)
    # result.root_key: use as your AES-256-GCM key etc.
    # result.header: prepend this to your ciphertext for later decryption

And to reverse it after loading a stored header:

    root_key = recover_root_key(keyset.private_handles, header)
"""

from __future__ import annotations

from dataclasses import dataclass

from .combiner import CombinedKeyMaterial, combine, combine_from_secrets
from .header import CryptoflexHeader
from .policy import Constraint, PolicyDecision, PolicyEngine
from .profiles import SecurityProfile


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


def establish_keys(
    engine: PolicyEngine | None = None,
    constraint: Constraint = Constraint.BALANCED,
    *,
    require_quantum_safe: bool = False,
) -> KeySet:
    """Generate a fresh keypair for every source in the policy-selected
    profile. Call this once per identity/session; keep private_handles
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


def derive_root_key(bundle: PublicBundle) -> DerivedRoot:
    """Given someone else's PublicBundle, derive a fresh root key and
    produce the header to send/store alongside your ciphertext."""
    from .profiles import get_profile

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
    header = CryptoflexHeader(
        profile_id=bundle.profile_id, components=combined.components
    )
    return DerivedRoot(root_key=combined.root_key, header=header)


def recover_root_key(private_handles: list[object], header: CryptoflexHeader) -> bytes:
    """Given the private handles from establish_keys() and a received
    header, recover the same root key derive_root_key() produced."""
    from .profiles import get_profile

    profile = get_profile(header.profile_id)
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
    return combined.root_key
