"""
Integration tests covering the full establish -> derive -> recover flow,
header round-tripping through raw bytes, and the migration scenario that
is the actual point of this library: a file encrypted under an OLD
profile must still decrypt correctly even after the policy engine's
current default has moved on.
"""

import pytest

from cryptoflex import profiles as profiles_module
from cryptoflex.api import derive_root_key, establish_keys, recover_root_key
from cryptoflex.header import CryptoflexHeader
from cryptoflex.policy import Constraint, PolicyDecision, PolicyEngine
from cryptoflex.profiles import SecurityProfile
from cryptoflex.sources import ClassicalSource, MockPQCSource


class _FixedProfileEngine:
    """Test-only stand-in for PolicyEngine that always returns a specific
    profile, so we can exercise the hybrid path using MockPQCSource
    without depending on liboqs being built in the test environment."""

    def __init__(self, profile: SecurityProfile):
        self._profile = profile

    def decide(self, constraint=Constraint.BALANCED, *, require_quantum_safe=False):
        return PolicyDecision(profile=self._profile, reason="forced for test", degraded=False)


@pytest.fixture
def hybrid_mock_profile():
    """Register a mock hybrid profile (X25519 + MockPQCSource) into the
    live profile registry for the duration of a test, then clean up."""
    profile = SecurityProfile(
        profile_id="hybrid_mock_test",
        display_name="Hybrid (test mock)",
        sources=[ClassicalSource(), MockPQCSource()],
        risk_tier="current",
    )
    profiles_module.PROFILES[profile.profile_id] = profile
    yield profile
    del profiles_module.PROFILES[profile.profile_id]


def test_full_handshake_classical_only():
    engine = PolicyEngine()
    keyset = establish_keys(engine, constraint=Constraint.FAST)
    assert keyset.profile.profile_id == "classical_only"

    derived = derive_root_key(keyset.public_bundle)
    recovered_key = recover_root_key(keyset.private_handles, derived.header)

    assert recovered_key == derived.root_key
    assert len(derived.root_key) == 32


def test_full_handshake_hybrid_mock(hybrid_mock_profile):
    engine = _FixedProfileEngine(hybrid_mock_profile)
    keyset = establish_keys(engine)
    assert keyset.profile.profile_id == "hybrid_mock_test"
    assert len(keyset.public_bundle.public_keys) == 2

    derived = derive_root_key(keyset.public_bundle)
    recovered_key = recover_root_key(keyset.private_handles, derived.header)

    assert recovered_key == derived.root_key


def test_header_survives_byte_round_trip_end_to_end():
    """Simulates actually writing the header to disk and reading it back,
    the same as a real vault file would."""
    engine = PolicyEngine()
    keyset = establish_keys(engine, constraint=Constraint.FAST)
    derived = derive_root_key(keyset.public_bundle)

    fake_ciphertext_payload = b"\x99" * 128
    blob_on_disk = derived.header.to_bytes() + fake_ciphertext_payload

    parsed_header, consumed = CryptoflexHeader.from_bytes(blob_on_disk)
    recovered_payload = blob_on_disk[consumed:]
    assert recovered_payload == fake_ciphertext_payload

    recovered_key = recover_root_key(keyset.private_handles, parsed_header)
    assert recovered_key == derived.root_key


def test_migration_scenario_old_profile_still_decrypts_after_policy_moves_on(
    hybrid_mock_profile,
):
    """The core promise of this library: encrypt something today under
    whatever the CURRENT default profile is, then simulate the policy
    engine's default changing later (e.g. a new package version prefers
    a different profile) - the OLD file must still decrypt correctly
    because the header pins the exact profile/components used at
    encryption time, independent of current policy.
    """
    # --- "today": encrypt under classical_only (e.g. FAST was policy then) ---
    old_engine = PolicyEngine()
    old_keyset = establish_keys(old_engine, constraint=Constraint.FAST)
    assert old_keyset.profile.profile_id == "classical_only"

    old_derived = derive_root_key(old_keyset.public_bundle)
    stored_blob = old_derived.header.to_bytes() + b"OLD-FILE-CIPHERTEXT-BYTES"

    # --- "years later": policy engine's default has moved to the hybrid
    # profile, but the recipient still has their old private handles and
    # must be able to read the old file ---
    new_engine = _FixedProfileEngine(hybrid_mock_profile)
    new_keyset = establish_keys(new_engine)
    assert new_keyset.profile.profile_id == "hybrid_mock_test"  # policy did change

    # decrypting the OLD file uses the header's own recorded profile
    # (classical_only), not whatever the engine's current default is
    parsed_header, consumed = CryptoflexHeader.from_bytes(stored_blob)
    assert parsed_header.profile_id == "classical_only"

    recovered_old_key = recover_root_key(old_keyset.private_handles, parsed_header)
    assert recovered_old_key == old_derived.root_key
    assert stored_blob[consumed:] == b"OLD-FILE-CIPHERTEXT-BYTES"


def test_recover_rejects_truncated_header_components(hybrid_mock_profile):
    """Regression test: a header with FEWER components than the profile
    expects (e.g. an attacker or corruption strips the PQC ciphertext,
    leaving only the classical one) must be rejected loudly, not silently
    accepted by deriving a key from a subset of sources. Previously a
    chained-comparison bug (`a != b != c`) let this slip through
    whenever len(profile.sources) == len(private_handles) but
    len(header.components) differed."""
    engine = _FixedProfileEngine(hybrid_mock_profile)
    keyset = establish_keys(engine)
    derived = derive_root_key(keyset.public_bundle)
    assert len(derived.header.components) == 2

    truncated_header = CryptoflexHeader(
        profile_id=derived.header.profile_id,
        components=derived.header.components[:1],  # drop the PQC component
    )

    with pytest.raises(ValueError, match="mismatched component counts"):
        recover_root_key(keyset.private_handles, truncated_header)


def test_recover_rejects_wrong_private_handles():
    """Using the WRONG party's private handles must not silently produce
    a plausible-looking-but-wrong key that happens to differ - it must
    differ, full stop, so a decryption step downstream fails loudly."""
    engine = PolicyEngine()
    keyset_a = establish_keys(engine, constraint=Constraint.FAST)
    keyset_b = establish_keys(engine, constraint=Constraint.FAST)

    derived = derive_root_key(keyset_a.public_bundle)
    wrong_key = recover_root_key(keyset_b.private_handles, derived.header)

    assert wrong_key != derived.root_key
