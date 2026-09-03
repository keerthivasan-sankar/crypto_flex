import pytest

from cryptoflex.api import DecryptionError, decrypt, encrypt, establish_keys
from cryptoflex.keystore import (
    MAGIC_KEYSTORE_ARGON2,
    MAGIC_KEYSTORE_SCRYPT,
    deserialize_public_bundle,
    export_keyset_bytes,
    import_keyset_bytes,
    serialize_public_bundle,
)
from cryptoflex.policy import Constraint, PolicyEngine


def test_public_bundle_serialization_round_trip():
    engine = PolicyEngine()
    keyset = establish_keys(engine, constraint=Constraint.FAST)

    json_str = serialize_public_bundle(keyset.public_bundle)
    recovered_bundle = deserialize_public_bundle(json_str)

    assert recovered_bundle.profile_id == keyset.public_bundle.profile_id
    assert len(recovered_bundle.public_keys) == len(keyset.public_bundle.public_keys)
    assert recovered_bundle.public_keys[0][0] == keyset.public_bundle.public_keys[0][0]
    assert recovered_bundle.public_keys[0][1] == keyset.public_bundle.public_keys[0][1]


def test_keyset_export_import_round_trip_argon2id():
    engine = PolicyEngine()
    keyset = establish_keys(engine, constraint=Constraint.FAST)

    password = "CorrectHorseBatteryStaple123!"
    encrypted_bytes = export_keyset_bytes(keyset, password, use_argon2=True)
    assert encrypted_bytes[:4] == MAGIC_KEYSTORE_ARGON2

    imported_keyset = import_keyset_bytes(encrypted_bytes, password)
    assert imported_keyset.profile.profile_id == keyset.profile.profile_id

    plaintext = b"Argon2id Keystore Import Functional Roundtrip"
    blob = encrypt(keyset.public_bundle, plaintext)
    decrypted = decrypt(imported_keyset.private_handles, blob)
    assert decrypted == plaintext


def test_keyset_export_import_round_trip_scrypt():
    engine = PolicyEngine()
    keyset = establish_keys(engine, constraint=Constraint.FAST)

    password = "CorrectHorseBatteryStaple123!"
    encrypted_bytes = export_keyset_bytes(keyset, password, use_argon2=False)
    assert encrypted_bytes[:4] == MAGIC_KEYSTORE_SCRYPT

    imported_keyset = import_keyset_bytes(encrypted_bytes, password)
    assert imported_keyset.profile.profile_id == keyset.profile.profile_id

    plaintext = b"Scrypt Keystore Import Functional Roundtrip"
    blob = encrypt(keyset.public_bundle, plaintext)
    decrypted = decrypt(imported_keyset.private_handles, blob)
    assert decrypted == plaintext


def test_keyset_export_import_round_trip_hybrid(hybrid_mock_profile, FixedProfileEngine):
    engine = FixedProfileEngine(hybrid_mock_profile)
    keyset = establish_keys(engine)

    password = "SuperSecretHybridPassword456!"
    encrypted_bytes = export_keyset_bytes(keyset, password)

    imported_keyset = import_keyset_bytes(encrypted_bytes, password)

    plaintext = b"Hybrid Keystore Payload"
    blob = encrypt(keyset.public_bundle, plaintext)
    decrypted = decrypt(imported_keyset.private_handles, blob)
    assert decrypted == plaintext


def test_keyset_import_wrong_password_raises_decryption_error():
    engine = PolicyEngine()
    keyset = establish_keys(engine, constraint=Constraint.FAST)

    password = "RightPassword"
    encrypted_bytes = export_keyset_bytes(keyset, password)

    with pytest.raises(DecryptionError):
        import_keyset_bytes(encrypted_bytes, "WrongPassword")


def test_keyset_import_corrupted_bytes_raises_decryption_error():
    engine = PolicyEngine()
    keyset = establish_keys(engine, constraint=Constraint.FAST)

    encrypted_bytes = bytearray(export_keyset_bytes(keyset, "password"))
    encrypted_bytes[10] ^= 0xFF

    with pytest.raises(DecryptionError):
        import_keyset_bytes(bytes(encrypted_bytes), "password")
