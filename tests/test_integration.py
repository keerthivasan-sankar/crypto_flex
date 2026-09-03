import pytest

from cryptoflex.api import DecryptionError, derive_root_key, establish_keys, recover_root_key
from cryptoflex.header import CryptoflexHeader
from cryptoflex.policy import Constraint, PolicyEngine


def test_full_handshake_classical_only():
    engine = PolicyEngine()
    keyset = establish_keys(engine, constraint=Constraint.FAST)
    assert keyset.profile.profile_id == "classical_only"

    derived = derive_root_key(keyset.public_bundle)
    recovered_key = recover_root_key(keyset.private_handles, derived.header)

    assert recovered_key == derived.root_key
    assert len(derived.root_key) == 32


def test_full_handshake_hybrid_mock(hybrid_mock_profile, FixedProfileEngine):
    engine = FixedProfileEngine(hybrid_mock_profile)
    keyset = establish_keys(engine)
    assert keyset.profile.profile_id == "hybrid_mock_test"
    assert len(keyset.public_bundle.public_keys) == 2

    derived = derive_root_key(keyset.public_bundle)
    recovered_key = recover_root_key(keyset.private_handles, derived.header)

    assert recovered_key == derived.root_key


def test_header_survives_byte_round_trip_end_to_end():
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
    FixedProfileEngine,
):
    # --- "today": encrypt under classical_only ---
    old_engine = PolicyEngine()
    old_keyset = establish_keys(old_engine, constraint=Constraint.FAST)
    assert old_keyset.profile.profile_id == "classical_only"

    old_derived = derive_root_key(old_keyset.public_bundle)
    stored_blob = old_derived.header.to_bytes() + b"OLD-FILE-CIPHERTEXT-BYTES"

    # --- "years later": policy engine default changes to hybrid ---
    new_engine = FixedProfileEngine(hybrid_mock_profile)
    new_keyset = establish_keys(new_engine)
    assert new_keyset.profile.profile_id == "hybrid_mock_test"

    parsed_header, consumed = CryptoflexHeader.from_bytes(stored_blob)
    assert parsed_header.profile_id == "classical_only"

    recovered_old_key = recover_root_key(old_keyset.private_handles, parsed_header)
    assert recovered_old_key == old_derived.root_key
    assert stored_blob[consumed:] == b"OLD-FILE-CIPHERTEXT-BYTES"


def test_recover_rejects_truncated_header_components(hybrid_mock_profile, FixedProfileEngine):
    engine = FixedProfileEngine(hybrid_mock_profile)
    keyset = establish_keys(engine)
    derived = derive_root_key(keyset.public_bundle)
    assert len(derived.header.components) == 2

    truncated_header = CryptoflexHeader(
        profile_id=derived.header.profile_id,
        components=derived.header.components[:1],
        nonce=derived.header.nonce,
    )

    with pytest.raises(DecryptionError):
        recover_root_key(keyset.private_handles, truncated_header)


def test_recover_rejects_wrong_private_handles():
    engine = PolicyEngine()
    keyset_a = establish_keys(engine, constraint=Constraint.FAST)
    keyset_b = establish_keys(engine, constraint=Constraint.FAST)

    derived = derive_root_key(keyset_a.public_bundle)
    wrong_key = recover_root_key(keyset_b.private_handles, derived.header)

    assert wrong_key != derived.root_key
