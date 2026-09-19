from __future__ import annotations

import pytest

from cryptoflex.api import decrypt, encrypt, establish_keys
from cryptoflex.errors import DecryptionError, DowngradeError
from cryptoflex.header import CryptoflexHeader
from cryptoflex.policy import Constraint, PolicyDecision
from cryptoflex.profiles import SecurityProfile, get_profile

PROFILE_IDS_BY_STRENGTH = ["classical_only", "hybrid_standard", "hybrid_high"]


def _profile_available(profile_id: str) -> bool:
    return get_profile(profile_id).is_available()


class _FixedEngine:
    def __init__(self, profile: SecurityProfile):
        self._profile = profile

    def decide(self, constraint=Constraint.BALANCED, *, require_quantum_safe=False):
        return PolicyDecision(
            profile=self._profile,
            reason="forced for test",
            degraded=False,
            min_accepted_profile=self._profile.profile_id,
        )


def _encrypt_under(profile_id: str, plaintext: bytes):
    """Encrypt plaintext under a specific named real profile (skipping
    the test if that profile isn't available in this environment, e.g.
    hybrid profiles when CRYPTOFLEX_DISABLE_PQC=1)."""
    profile = get_profile(profile_id)
    if not profile.is_available():
        pytest.skip(f"profile '{profile_id}' not available in this environment")
    keyset = establish_keys(engine=_FixedEngine(profile))
    blob = encrypt(keyset.public_bundle, plaintext)
    return keyset, blob


# --- Matrix: (claimed/actual profile) x (requested min_profile) --------

MATRIX_CASES = [
    # (actual_profile, requested_min_profile, expect_downgrade_error)
    ("classical_only", None, False),
    ("classical_only", "classical_only", False),
    ("classical_only", "hybrid_standard", True),
    ("classical_only", "hybrid_high", True),
    ("hybrid_standard", None, False),
    ("hybrid_standard", "classical_only", False),
    ("hybrid_standard", "hybrid_standard", False),
    ("hybrid_standard", "hybrid_high", True),
    ("hybrid_high", None, False),
    ("hybrid_high", "classical_only", False),
    ("hybrid_high", "hybrid_standard", False),
    ("hybrid_high", "hybrid_high", False),
]


@pytest.mark.parametrize("actual_profile,requested_min,expect_downgrade", MATRIX_CASES)
def test_min_profile_matrix(actual_profile, requested_min, expect_downgrade):
    plaintext = b"downgrade matrix test payload"
    keyset, blob = _encrypt_under(actual_profile, plaintext)

    if expect_downgrade:
        with pytest.raises(DowngradeError):
            decrypt(keyset.private_handles, blob, min_profile=requested_min)
    else:
        result = decrypt(keyset.private_handles, blob, min_profile=requested_min)
        assert result == plaintext


def test_downgrade_error_is_a_decryption_error_subclass():
    """DowngradeError must remain catchable via the generic
    DecryptionError boundary too, per api.py's own documented design,
    while still being distinguishable via its own type when a caller
    wants to tell 'policy refusal' apart from 'crypto failure'."""
    assert issubclass(DowngradeError, DecryptionError)


# --- Header tampering: claimed profile doesn't match actual ciphertext ---


def test_tampering_profile_id_to_claim_a_different_profile_is_rejected():
    """Rewriting header.profile_id to claim a different (even a
    'stronger'-sounding) profile than what the ciphertext components
    actually match must be rejected - not silently accepted just
    because the claimed profile_id string looks acceptable to a
    min_profile check performed before the ciphertext is even
    examined. The header AAD binding (existing feature) is what
    actually catches this."""
    keyset, blob = _encrypt_under("classical_only", b"tamper profile_id test")
    header, consumed = CryptoflexHeader.from_bytes(blob)

    fake_header = CryptoflexHeader(
        profile_id="hybrid_standard",  # lies about being stronger
        components=header.components,  # but ciphertext is still classical_only's
        nonce=header.nonce,
    )
    tampered_blob = fake_header.to_bytes() + blob[consumed:]

    with pytest.raises(DecryptionError):
        decrypt(keyset.private_handles, tampered_blob)


def test_tampering_profile_id_to_malformed_value_is_rejected():
    """A header claiming a profile_id that doesn't exist at all must
    fail cleanly, not crash with an unrelated exception type."""
    keyset, blob = _encrypt_under("classical_only", b"malformed profile_id test")
    header, consumed = CryptoflexHeader.from_bytes(blob)

    fake_header = CryptoflexHeader(
        profile_id="this-profile-does-not-exist",
        components=header.components,
        nonce=header.nonce,
    )
    tampered_blob = fake_header.to_bytes() + blob[consumed:]

    with pytest.raises(DecryptionError):
        decrypt(keyset.private_handles, tampered_blob)


# --- Rollback: an OLD ciphertext must still decrypt under its own profile ---


def test_rollback_old_ciphertext_still_decrypts_after_policy_moves_on():
    """This is intended behavior, not a vulnerability: a file encrypted
    under an older/weaker profile must remain decryptable later, even
    after the policy engine's current default has moved on to a
    stronger profile - that's the entire point of the versioned header
    and the migration tooling. This test proves that intent holds,
    rather than assuming it."""
    old_keyset, old_blob = _encrypt_under("classical_only", b"old profile payload")

    # Simulate time passing: the "current" policy default is now
    # hybrid_standard (if available) or otherwise unchanged - either
    # way, the OLD keyset/blob pair must still decrypt correctly using
    # its own recorded profile, independent of whatever the engine's
    # present-day default is.
    result = decrypt(old_keyset.private_handles, old_blob)
    assert result == b"old profile payload"

    # And explicitly requesting the OLD (weaker) profile as the
    # min_profile must still succeed - rollback protection should not
    # accidentally forbid legitimately reading your own old data when
    # you ask for exactly the profile it was encrypted under.
    result2 = decrypt(old_keyset.private_handles, old_blob, min_profile="classical_only")
    assert result2 == b"old profile payload"


def test_rollback_replaying_old_ciphertext_against_stricter_requirement_is_rejected():
    """The flip side of the rollback test above: if a CALLER now
    requires a minimum profile stronger than what an old ciphertext
    was actually encrypted under, replaying that old ciphertext must
    be rejected - the caller's current policy is what's enforced, not
    whatever was acceptable at encryption time."""
    old_keyset, old_blob = _encrypt_under("classical_only", b"old profile payload")

    with pytest.raises(DowngradeError):
        decrypt(old_keyset.private_handles, old_blob, min_profile="hybrid_standard")
