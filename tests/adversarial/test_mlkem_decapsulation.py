# tests/adversarial/test_mlkem_decapsulation.py
"""Adversarial tests for ML-KEM decapsulation length validation and error handling.
These tests are conditional on liboqs being available. They are skipped otherwise.
"""

import os
import pytest

from cryptoflex.api import DecryptionError, decrypt, encrypt, establish_keys
from cryptoflex.header import CryptoflexHeader
from cryptoflex.policy import Constraint, PolicyEngine
from cryptoflex.sources import PQCSource


@pytest.fixture(scope="module")
def pqc_source():
    src = PQCSource()
    if not src.is_available():
        pytest.skip("PQCSource not available – liboqs not installed")
    return src


def test_ciphertext_invalid_length_validation(pqc_source):
    """Verify that PQCSource.decapsulate explicitly rejects invalid-length ciphertexts."""
    pub, priv = pqc_source.generate_keypair()
    enc = pqc_source.encapsulate(pub)
    expected_len = len(enc.ciphertext)

    # Truncated ciphertext: must fail CryptoFlex explicit length check
    truncated = enc.ciphertext[: expected_len // 2]
    with pytest.raises(ValueError, match="Invalid ciphertext length"):
        pqc_source.decapsulate(priv, truncated)

    # Extended ciphertext (+1 byte): must fail CryptoFlex explicit length check
    extended = enc.ciphertext + b"\x00"
    with pytest.raises(ValueError, match="Invalid ciphertext length"):
        pqc_source.decapsulate(priv, extended)


def test_ciphertext_valid_length_malformed_decapsulation(pqc_source):
    """Verify that a valid-length malformed ML-KEM ciphertext passes length validation
    and exercises native liboqs decapsulation (implicit rejection returning a 32-byte secret
    differing from valid encapsulation).
    """
    pub, priv = pqc_source.generate_keypair()
    enc = pqc_source.encapsulate(pub)
    expected_len = len(enc.ciphertext)

    # Valid-length malformed ciphertext
    random_ct = os.urandom(expected_len)

    # Native ML-KEM (liboqs / FIPS 203) performs implicit rejection:
    # It must NOT fail CryptoFlex length validation, MUST return a 32-byte secret,
    # and the derived secret MUST differ from the true encapsulation secret.
    recovered_ss = pqc_source.decapsulate(priv, random_ct)

    assert isinstance(recovered_ss, bytes)
    assert len(recovered_ss) == 32
    assert recovered_ss != enc.shared_secret


def test_high_level_malformed_pqc_ciphertext_raises_decryption_error(pqc_source):
    """Verify that passing a malformed valid-length ML-KEM ciphertext into high-level decrypt()
    results in AEAD authentication failure and raises DecryptionError.
    """
    engine = PolicyEngine()
    keyset = establish_keys(engine, Constraint.BALANCED)
    pt = b"adversarial-test-payload"
    blob = encrypt(keyset.public_bundle, pt)

    header, consumed = CryptoflexHeader.from_bytes(blob)
    payload = blob[consumed:]

    tampered_components = []
    for alg_id, ct in header.components:
        if "mlkem" in alg_id:
            # Replace ML-KEM ciphertext with valid-length random bytes
            tampered_components.append((alg_id, os.urandom(len(ct))))
        else:
            tampered_components.append((alg_id, ct))

    tampered_header = CryptoflexHeader(
        profile_id=header.profile_id,
        components=tampered_components,
        nonce=header.nonce,
    )
    tampered_blob = tampered_header.to_bytes() + payload

    with pytest.raises(DecryptionError):
        decrypt(keyset.private_handles, tampered_blob)
