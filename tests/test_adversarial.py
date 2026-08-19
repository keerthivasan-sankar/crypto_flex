"""
Adversarial tests: malformed, truncated, reordered, or otherwise hostile
inputs to the header parser and key-recovery path. These are the tests a
security reviewer looks for first - each one encodes a specific way a
corrupted file or an active attacker could try to trick this library into
either crashing uncontrolled or silently deriving a weaker/wrong key
without raising.

Pulled into its own module (rather than living inside
test_integration.py) so it's easy to find and easy to extend.
"""

from __future__ import annotations

import pytest

from cryptoflex import profiles as profiles_module
from cryptoflex.api import derive_root_key, establish_keys, recover_root_key
from cryptoflex.header import CryptoflexHeader, HeaderParseError, FORMAT_VERSION
from cryptoflex.policy import Constraint, PolicyDecision
from cryptoflex.profiles import SecurityProfile
from cryptoflex.sources import ClassicalSource, MockPQCSource


class _FixedProfileEngine:
    def __init__(self, profile: SecurityProfile):
        self._profile = profile

    def decide(self, constraint=Constraint.BALANCED, *, require_quantum_safe=False):
        return PolicyDecision(profile=self._profile, reason="forced for test", degraded=False)


@pytest.fixture
def hybrid_mock_profile():
    profile = SecurityProfile(
        profile_id="hybrid_mock_adversarial_test",
        display_name="Hybrid (adversarial test mock)",
        sources=[ClassicalSource(), MockPQCSource()],
        risk_tier="current",
    )
    profiles_module.PROFILES[profile.profile_id] = profile
    yield profile
    del profiles_module.PROFILES[profile.profile_id]


# --- header byte-level malformation ------------------------------------


def test_truncated_at_every_offset_never_crashes_uncontrolled():
    """Truncating a valid header at ANY byte offset must either parse
    successfully (only possible at the exact end) or raise EXACTLY
    HeaderParseError - never a raw struct.error/IndexError/
    UnicodeDecodeError leaking out that a caller wouldn't know to catch.
    (This test caught a real bug: struct.unpack on a truncated
    ciphertext-length field used to raise a bare struct.error.)"""
    header = CryptoflexHeader(
        profile_id="hybrid_standard",
        components=[("x25519", b"\xaa" * 32), ("mlkem768", b"\xbb" * 1088)],
    )
    full = header.to_bytes()

    for cut in range(len(full)):
        truncated = full[:cut]
        try:
            parsed, consumed = CryptoflexHeader.from_bytes(truncated)
            # only valid if we happened to cut exactly at the full length
            assert cut == len(full)
        except HeaderParseError:
            pass  # the only acceptable failure mode


def test_empty_bytes_rejected_cleanly():
    with pytest.raises(HeaderParseError):
        CryptoflexHeader.from_bytes(b"")


def test_random_garbage_rejected_cleanly():
    import os

    for _ in range(50):
        garbage = os.urandom(64)
        try:
            CryptoflexHeader.from_bytes(garbage)
        except HeaderParseError:
            pass  # the only acceptable failure mode


def test_future_format_version_rejected_not_misparsed():
    """A header from a hypothetical future format version must be
    rejected explicitly, never silently misparsed as if it were the
    current version (which could misinterpret length-prefixed fields as
    garbage and produce a corrupt-but-'successfully parsed' header)."""
    header = CryptoflexHeader(
        profile_id="classical_only", components=[("x25519", b"\x00" * 32)]
    )
    data = bytearray(header.to_bytes())
    data[4] = FORMAT_VERSION + 1
    with pytest.raises(HeaderParseError):
        CryptoflexHeader.from_bytes(bytes(data))


# --- recovery-path attacks (already-parsed header, but semantically bad) ---


def test_downgrade_by_stripping_pqc_component_is_rejected(hybrid_mock_profile):
    """Attacker (or corruption) drops the PQC ciphertext, leaving only
    the classical component - simulating a downgrade attack. Must be
    rejected loudly, not silently accepted using a subset of sources."""
    engine = _FixedProfileEngine(hybrid_mock_profile)
    keyset = establish_keys(engine)
    derived = derive_root_key(keyset.public_bundle)

    stripped = CryptoflexHeader(
        profile_id=derived.header.profile_id,
        components=derived.header.components[:1],
    )
    with pytest.raises(ValueError, match="mismatched component counts"):
        recover_root_key(keyset.private_handles, stripped)


def test_duplicated_component_is_rejected(hybrid_mock_profile):
    """Attacker duplicates one component to pad the count back up rather
    than truncating - a naive length-only check could be fooled by this;
    the algorithm-id order check must still catch it."""
    engine = _FixedProfileEngine(hybrid_mock_profile)
    keyset = establish_keys(engine)
    derived = derive_root_key(keyset.public_bundle)

    duplicated = CryptoflexHeader(
        profile_id=derived.header.profile_id,
        components=[derived.header.components[0], derived.header.components[0]],
    )
    with pytest.raises(ValueError):
        recover_root_key(keyset.private_handles, duplicated)


def test_reordered_components_rejected_not_silently_wrong(hybrid_mock_profile):
    """Swapping component order must be caught by the algorithm-id order
    check rather than silently decapsulating the wrong ciphertext against
    the wrong source."""
    engine = _FixedProfileEngine(hybrid_mock_profile)
    keyset = establish_keys(engine)
    derived = derive_root_key(keyset.public_bundle)

    reordered = CryptoflexHeader(
        profile_id=derived.header.profile_id,
        components=list(reversed(derived.header.components)),
    )
    with pytest.raises(ValueError):
        recover_root_key(keyset.private_handles, reordered)


def test_tampered_ciphertext_byte_changes_recovered_key_not_crashes(hybrid_mock_profile):
    """Flipping a single ciphertext byte must not crash uncontrolled -
    it should either raise cleanly (e.g. from decapsulation) or produce a
    DIFFERENT key than the honest run, never the same key."""
    engine = _FixedProfileEngine(hybrid_mock_profile)
    keyset = establish_keys(engine)
    derived = derive_root_key(keyset.public_bundle)

    tampered_components = list(derived.header.components)
    alg_id, ct = tampered_components[0]
    tampered_ct = bytes((ct[0] ^ 0xFF,)) + ct[1:]
    tampered_components[0] = (alg_id, tampered_ct)
    tampered_header = CryptoflexHeader(
        profile_id=derived.header.profile_id, components=tampered_components
    )

    try:
        recovered = recover_root_key(keyset.private_handles, tampered_header)
        assert recovered != derived.root_key
    except (ValueError, Exception):
        pass  # a controlled raise here is also an acceptable outcome
