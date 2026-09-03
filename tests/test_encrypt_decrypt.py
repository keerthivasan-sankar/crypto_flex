import pytest

from cryptoflex.api import DecryptionError, DowngradeError, decrypt, encrypt, establish_keys
from cryptoflex.policy import Constraint, PolicyEngine


def test_encrypt_decrypt_round_trip_classical():
    engine = PolicyEngine()
    keyset = establish_keys(engine, constraint=Constraint.FAST)

    plaintext = b"Top Secret Payload: Post-Quantum Migration in Progress!"
    blob = encrypt(keyset.public_bundle, plaintext)

    decrypted = decrypt(keyset.private_handles, blob)
    assert decrypted == plaintext


def test_encrypt_decrypt_round_trip_hybrid(hybrid_mock_profile, FixedProfileEngine):
    engine = FixedProfileEngine(hybrid_mock_profile)
    keyset = establish_keys(engine)

    plaintext = b"Hybrid Encrypted Message"
    blob = encrypt(keyset.public_bundle, plaintext)

    decrypted = decrypt(keyset.private_handles, blob)
    assert decrypted == plaintext


def test_decrypt_rejects_tampered_header_aad():
    """Modifying a single byte in the header section of the blob must cause
    AEAD authentication failure, resulting in uniform DecryptionError."""
    engine = PolicyEngine()
    keyset = establish_keys(engine, constraint=Constraint.FAST)

    plaintext = b"Sensitive Data"
    blob = bytearray(encrypt(keyset.public_bundle, plaintext))

    # Flip a byte in the magic or profile ID string within header
    blob[2] ^= 0xFF

    with pytest.raises(DecryptionError):
        decrypt(keyset.private_handles, bytes(blob))


def test_decrypt_rejects_tampered_ciphertext_payload():
    """Modifying a byte in the AEAD payload section must trigger AEAD tag failure."""
    engine = PolicyEngine()
    keyset = establish_keys(engine, constraint=Constraint.FAST)

    plaintext = b"Sensitive Data"
    blob = bytearray(encrypt(keyset.public_bundle, plaintext))

    # Flip the last byte of the AEAD ciphertext/tag
    blob[-1] ^= 0xFF

    with pytest.raises(DecryptionError):
        decrypt(keyset.private_handles, bytes(blob))


def test_decrypt_rejects_wrong_private_handles():
    engine = PolicyEngine()
    keyset_a = establish_keys(engine, constraint=Constraint.FAST)
    keyset_b = establish_keys(engine, constraint=Constraint.FAST)

    blob = encrypt(keyset_a.public_bundle, b"Secret")

    with pytest.raises(DecryptionError):
        decrypt(keyset_b.private_handles, blob)


def test_min_profile_enforcement_passes_when_equal_or_stronger(
    hybrid_mock_profile, FixedProfileEngine
):
    engine = FixedProfileEngine(hybrid_mock_profile)
    keyset = establish_keys(engine)

    blob = encrypt(keyset.public_bundle, b"Hybrid Data")

    # Asking for classical_only (strength 0) when blob is hybrid_mock_test (strength 1) is allowed
    decrypted = decrypt(keyset.private_handles, blob, min_profile="classical_only")
    assert decrypted == b"Hybrid Data"

    # Asking for hybrid_mock_test (strength 1) when blob is hybrid_mock_test (strength 1) is allowed
    decrypted2 = decrypt(keyset.private_handles, blob, min_profile="hybrid_mock_test")
    assert decrypted2 == b"Hybrid Data"


def test_min_profile_enforcement_raises_downgrade_error():
    """If caller requires hybrid_standard (strength 1) but blob is classical_only (strength 0),
    DowngradeError must be raised BEFORE attempting decryption."""
    engine = PolicyEngine()
    keyset = establish_keys(engine, constraint=Constraint.FAST)

    blob = encrypt(keyset.public_bundle, b"Weak Data")

    with pytest.raises(DowngradeError):
        decrypt(keyset.private_handles, blob, min_profile="hybrid_standard")
