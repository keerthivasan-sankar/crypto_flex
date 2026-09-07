import json
import os
import binascii

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptoflex.combiner import combine_from_secrets, _encode_info
from cryptoflex.header import CryptoflexHeader

def _write_vector(filename, data):
    out_dir = os.path.join(os.path.dirname(__file__), "vectors")
    os.makedirs(out_dir, exist_ok=True)
    with open(os.path.join(out_dir, filename), "w") as f:
        json.dump(data, f, indent=4)

def gen_hybrid_standard_vector():
    # Deterministic X25519
    priv_bytes = bytes([1] * 32)
    priv = X25519PrivateKey.from_private_bytes(priv_bytes)
    pub = priv.public_key().public_bytes_raw()

    peer_priv_bytes = bytes([2] * 32)
    peer_priv = X25519PrivateKey.from_private_bytes(peer_priv_bytes)
    peer_pub = peer_priv.public_key().public_bytes_raw()
    shared_secret = peer_priv.exchange(priv.public_key())

    # We mock PQC (ML-KEM-768) encapsulation output
    pqc_ciphertext = bytes([3] * 1088)
    pqc_shared_secret = bytes([4] * 32)

    shared_secrets = [
        ("x25519", shared_secret),
        ("mlkem768", pqc_shared_secret)
    ]
    ciphertexts = [
        ("x25519", peer_pub),
        ("mlkem768", pqc_ciphertext)
    ]

    ikm = b"".join(secret for _, secret in shared_secrets)
    info = _encode_info(b"cryptoflex-hybrid-kem-combiner", ciphertexts)

    combined = combine_from_secrets(shared_secrets, ciphertexts)
    root_key = combined.root_key

    # We also mock the components for the header
    header = CryptoflexHeader(
        profile_id="hybrid_standard",
        components=ciphertexts,
        nonce=bytes([5] * 12)
    )
    header_bytes = header.to_bytes()

    vector = {
        "description": "Deterministic test vector for hybrid_standard profile combiner and header encoding",
        "algorithm": "hybrid_standard",
        "inputs": {
            "x25519_initiator_private": binascii.hexlify(peer_priv_bytes).decode(),
            "x25519_responder_public": binascii.hexlify(pub).decode(),
            "mlkem768_ciphertext": binascii.hexlify(pqc_ciphertext).decode(),
            "mlkem768_shared_secret": binascii.hexlify(pqc_shared_secret).decode(),
            "nonce": binascii.hexlify(bytes([5] * 12)).decode(),
        },
        "expected_outputs": {
            "ikm": binascii.hexlify(ikm).decode(),
            "info_context": binascii.hexlify(info).decode(),
            "derived_root_key": binascii.hexlify(root_key).decode(),
            "header_encoding": binascii.hexlify(header_bytes).decode()
        },
        "test_only": "Uses mocked deterministic byte arrays for ML-KEM outputs."
    }
    _write_vector("hybrid_standard_vector.json", vector)


def gen_x25519_only_vector():
    priv_bytes = bytes([6] * 32)
    priv = X25519PrivateKey.from_private_bytes(priv_bytes)
    pub = priv.public_key().public_bytes_raw()

    peer_priv_bytes = bytes([7] * 32)
    peer_priv = X25519PrivateKey.from_private_bytes(peer_priv_bytes)
    peer_pub = peer_priv.public_key().public_bytes_raw()
    shared_secret = peer_priv.exchange(priv.public_key())

    shared_secrets = [("x25519", shared_secret)]
    ciphertexts = [("x25519", peer_pub)]

    ikm = b"".join(secret for _, secret in shared_secrets)
    info = _encode_info(b"cryptoflex-hybrid-kem-combiner", ciphertexts)
    combined = combine_from_secrets(shared_secrets, ciphertexts)

    header = CryptoflexHeader(
        profile_id="classical_only",
        components=ciphertexts,
        nonce=bytes([8] * 12)
    )

    vector = {
        "description": "Deterministic test vector for classical_only profile combiner and header encoding",
        "algorithm": "classical_only",
        "inputs": {
            "x25519_initiator_private": binascii.hexlify(peer_priv_bytes).decode(),
            "x25519_responder_public": binascii.hexlify(pub).decode(),
            "nonce": binascii.hexlify(bytes([8] * 12)).decode(),
        },
        "expected_outputs": {
            "ikm": binascii.hexlify(ikm).decode(),
            "info_context": binascii.hexlify(info).decode(),
            "derived_root_key": binascii.hexlify(combined.root_key).decode(),
            "header_encoding": binascii.hexlify(header.to_bytes()).decode()
        }
    }
    _write_vector("x25519_only_vector.json", vector)


def gen_mlkem1024_hybrid_vector():
    priv_bytes = bytes([9] * 32)
    priv = X25519PrivateKey.from_private_bytes(priv_bytes)
    pub = priv.public_key().public_bytes_raw()

    peer_priv_bytes = bytes([10] * 32)
    peer_priv = X25519PrivateKey.from_private_bytes(peer_priv_bytes)
    peer_pub = peer_priv.public_key().public_bytes_raw()
    shared_secret = peer_priv.exchange(priv.public_key())

    pqc_ciphertext = bytes([11] * 1568)
    pqc_shared_secret = bytes([12] * 32)

    shared_secrets = [
        ("x25519", shared_secret),
        ("mlkem1024", pqc_shared_secret)
    ]
    ciphertexts = [
        ("x25519", peer_pub),
        ("mlkem1024", pqc_ciphertext)
    ]

    ikm = b"".join(secret for _, secret in shared_secrets)
    info = _encode_info(b"cryptoflex-hybrid-kem-combiner", ciphertexts)
    combined = combine_from_secrets(shared_secrets, ciphertexts)

    header = CryptoflexHeader(
        profile_id="hybrid_high",
        components=ciphertexts,
        nonce=bytes([13] * 12)
    )

    vector = {
        "description": "Deterministic test vector for hybrid_high profile (ML-KEM-1024 + X25519)",
        "algorithm": "hybrid_high",
        "inputs": {
            "x25519_initiator_private": binascii.hexlify(peer_priv_bytes).decode(),
            "x25519_responder_public": binascii.hexlify(pub).decode(),
            "mlkem1024_ciphertext": binascii.hexlify(pqc_ciphertext).decode(),
            "mlkem1024_shared_secret": binascii.hexlify(pqc_shared_secret).decode(),
            "nonce": binascii.hexlify(bytes([13] * 12)).decode(),
        },
        "expected_outputs": {
            "ikm": binascii.hexlify(ikm).decode(),
            "info_context": binascii.hexlify(info).decode(),
            "derived_root_key": binascii.hexlify(combined.root_key).decode(),
            "header_encoding": binascii.hexlify(header.to_bytes()).decode()
        },
        "test_only": "Non-cryptographic mock vector based on ML-KEM-1024 lengths (1568 bytes ciphertext), meant for parsing/format checks."
    }
    _write_vector("mlkem1024_hybrid_vector.json", vector)


def gen_auth_failure_vector():
    vector = {
        "description": "Vector representing an authentication failure (e.g., AEAD tag mismatch or header manipulation)",
        "algorithm": "hybrid_standard",
        "inputs": {
            "tampered_header_or_tag": "true",
            "tampered_bit": "0x01 flipped in AAD"
        },
        "expected_failure": {
            "exception": "DecryptionError",
            "reason": "Tampered AAD causes AES-GCM to reject the ciphertext, collapsing into a unified DecryptionError at the API boundary."
        }
    }
    _write_vector("authentication_failure_vector.json", vector)


def gen_malformed_length_vector():
    vector = {
        "description": "Vector representing a malformed ciphertext length for a KEM primitive",
        "algorithm": "mlkem768",
        "inputs": {
            "expected_length": 1088,
            "actual_length": 1087,
            "ciphertext": binascii.hexlify(bytes([3] * 1087)).decode()
        },
        "expected_failure": {
            "exception": "ValueError",
            "reason": "Length prefix/validation dynamically checks exact ciphertext length against algorithm metadata, rejecting malformed inputs cleanly."
        }
    }
    _write_vector("malformed_length_vector.json", vector)


def generate_all():
    gen_hybrid_standard_vector()
    gen_x25519_only_vector()
    gen_mlkem1024_hybrid_vector()
    gen_auth_failure_vector()
    gen_malformed_length_vector()

if __name__ == "__main__":
    generate_all()
