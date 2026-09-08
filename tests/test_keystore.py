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


def test_export_rejects_profile_mismatch():
    engine = PolicyEngine()
    keyset = establish_keys(engine, constraint=Constraint.FAST)
    keyset.public_bundle.profile_id = "bogus_profile"
    with pytest.raises(ValueError, match="profile mismatch"):
        export_keyset_bytes(keyset, "password")


def test_export_rejects_component_count_mismatch():
    engine = PolicyEngine()
    keyset = establish_keys(engine, constraint=Constraint.FAST)
    keyset.public_bundle.public_keys.pop()
    with pytest.raises(ValueError, match="component count mismatch"):
        export_keyset_bytes(keyset, "password")


def test_import_rejects_invalid_profile_id():
    import json, os
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptoflex.keystore import MAGIC_KEYSTORE_ARGON2, _derive_wrapping_key, SALT_LEN, NONCE_LEN

    payload = {
        "profile_id": "nonexistent_profile_id",
        "public_bundle": {"profile_id": "nonexistent_profile_id", "public_keys": []},
        "private_handles": []
    }
    plaintext = json.dumps(payload).encode("utf-8")
    salt = os.urandom(SALT_LEN)
    nonce = os.urandom(NONCE_LEN)
    wrapping_key = _derive_wrapping_key("pass", salt, "argon2id")
    aesgcm = AESGCM(wrapping_key)
    ct = aesgcm.encrypt(nonce, plaintext, MAGIC_KEYSTORE_ARGON2)
    blob = MAGIC_KEYSTORE_ARGON2 + salt + nonce + ct

    with pytest.raises(DecryptionError, match="unrecognized profile"):
        import_keyset_bytes(blob, "pass")


def test_deserialize_public_bundle_rejects_garbage_base64():
    json_str = '{"profile_id": "classical_only", "public_keys": [{"alg_id": "x25519", "key_b64": "not_base_64!@#"}]}'
    with pytest.raises(DecryptionError, match="Malformed public bundle"):
        deserialize_public_bundle(json_str)


def test_import_rejects_garbage_base64_private_handle():
    import json, os
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptoflex.keystore import MAGIC_KEYSTORE_ARGON2, _derive_wrapping_key, SALT_LEN, NONCE_LEN
    
    payload = {
        "profile_id": "classical_only",
        "public_bundle": {"profile_id": "classical_only", "public_keys": [{"alg_id": "x25519", "key_b64": "aaaa"}]},
        "private_handles": [{"alg_id": "x25519", "priv_b64": "not_base_64!@#"}]
    }
    plaintext = json.dumps(payload).encode("utf-8")
    salt = os.urandom(SALT_LEN)
    nonce = os.urandom(NONCE_LEN)
    wrapping_key = _derive_wrapping_key("pass", salt, "argon2id")
    aesgcm = AESGCM(wrapping_key)
    ct = aesgcm.encrypt(nonce, plaintext, MAGIC_KEYSTORE_ARGON2)
    blob = MAGIC_KEYSTORE_ARGON2 + salt + nonce + ct
    
    with pytest.raises(DecryptionError, match="failed to deserialize private key"):
        import_keyset_bytes(blob, "pass")


# ============================================================================
# Keystore hardening tests
# ============================================================================

def test_keystore_rejects_empty_password_str():
    """An empty string password must be rejected before KDF runs."""
    engine = PolicyEngine()
    keyset = establish_keys(engine, constraint=Constraint.FAST)
    with pytest.raises(ValueError, match="must not be empty"):
        export_keyset_bytes(keyset, "")


def test_keystore_rejects_empty_password_bytes():
    """An empty bytes password must be rejected before KDF runs."""
    engine = PolicyEngine()
    keyset = establish_keys(engine, constraint=Constraint.FAST)
    with pytest.raises(ValueError, match="must not be empty"):
        export_keyset_bytes(keyset, b"")


def test_keystore_rejects_oversized_input():
    """An import blob exceeding MAX_KEYSTORE_SIZE must be rejected before any KDF attempt."""
    from cryptoflex.keystore import MAX_KEYSTORE_SIZE
    big_blob = b"CFLA" + b"\\x00" * (MAX_KEYSTORE_SIZE + 1)
    with pytest.raises(DecryptionError, match="exceeds maximum"):
        import_keyset_bytes(big_blob, "anypassword")


def test_keystore_rejects_profile_id_mismatch():
    """A keystore whose internal profile_id differs from its public_bundle profile_id must fail."""
    import json
    import os
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptoflex.keystore import (
        MAGIC_KEYSTORE_ARGON2, SALT_LEN, NONCE_LEN,
        _derive_wrapping_key,
    )

    # Construct a keystore where profile_id says 'classical_only' but
    # public_bundle says 'hybrid_standard' — cross-binding should catch this.
    payload = {
        "profile_id": "classical_only",
        "public_bundle": {
            "profile_id": "hybrid_standard",  # mismatch
            "public_keys": [
                {"alg_id": "x25519", "key_b64": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="},
            ]
        },
        "private_handles": [
            {"alg_id": "x25519", "priv_b64": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="}
        ]
    }
    plaintext = json.dumps(payload).encode("utf-8")
    salt = os.urandom(SALT_LEN)
    nonce = os.urandom(NONCE_LEN)
    wrapping_key = _derive_wrapping_key("pass", salt, "argon2id")
    aesgcm = AESGCM(wrapping_key)
    ct = aesgcm.encrypt(nonce, plaintext, MAGIC_KEYSTORE_ARGON2)
    blob = MAGIC_KEYSTORE_ARGON2 + salt + nonce + ct

    with pytest.raises(DecryptionError):
        import_keyset_bytes(blob, "pass")
