import json
import os
import binascii

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptoflex.combiner import combine_from_secrets, _encode_info
from cryptoflex.header import CryptoflexHeader

def generate_vectors():
    out_dir = os.path.join(os.path.dirname(__file__), "vectors")
    os.makedirs(out_dir, exist_ok=True)

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
        "inputs": {
            "x25519_initiator_private": binascii.hexlify(peer_priv_bytes).decode(),
            "x25519_responder_public": binascii.hexlify(pub).decode(),
            "mlkem768_ciphertext": binascii.hexlify(pqc_ciphertext).decode(),
            "mlkem768_shared_secret": binascii.hexlify(pqc_shared_secret).decode(),
            "nonce": binascii.hexlify(bytes([5] * 12)).decode(),
        },
        "combiner": {
            "ikm": binascii.hexlify(ikm).decode(),
            "info_context": binascii.hexlify(info).decode(),
            "derived_root_key": binascii.hexlify(root_key).decode()
        },
        "header_encoding": {
            "version": header.version,
            "profile_id": header.profile_id,
            "encoded_bytes": binascii.hexlify(header_bytes).decode()
        }
    }

    with open(os.path.join(out_dir, "hybrid_standard_vector.json"), "w") as f:
        json.dump(vector, f, indent=4)


if __name__ == "__main__":
    generate_vectors()
