import binascii
import json
import os
import struct

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

VECTORS_DIR = os.path.join(os.path.dirname(__file__), "vectors")

def _encode_info(context: bytes, components: list[tuple[str, bytes]]) -> bytes:
    """Independent implementation of the FORMAT_SPECIFICATION.md info encoding."""
    out = bytearray()
    out += struct.pack(">H", 2)
    out += struct.pack(">I", len(context))
    out += context
    out += struct.pack(">H", len(components))
    for alg_id, ct in components:
        alg_bytes = alg_id.encode("utf-8")
        out += struct.pack(">I", len(alg_bytes))
        out += alg_bytes
        out += struct.pack(">I", len(ct))
        out += ct
    return bytes(out)

def _encode_header(profile_id: str, components: list[tuple[str, bytes]], nonce: bytes) -> bytes:
    """Independent implementation of the FORMAT_SPECIFICATION.md header encoding."""
    out = bytearray()
    out += b"CFLX"
    out += bytes([2])
    profile_bytes = profile_id.encode("utf-8")
    out += bytes([len(profile_bytes)])
    out += profile_bytes
    out += bytes([len(components)])
    for alg_id, ct in components:
        alg_bytes = alg_id.encode("utf-8")
        out += bytes([len(alg_bytes)])
        out += alg_bytes
        out += struct.pack(">H", len(ct))
        out += ct
    out += nonce
    return bytes(out)

def test_independent_vectors():
    """
    Independently verify the JSON test vectors without using CryptoFlex's internal
    combiner or header serialization logic.
    """
    assert os.path.exists(VECTORS_DIR), "Vectors directory not found"
    
    for filename in os.listdir(VECTORS_DIR):
        if not filename.endswith(".json"):
            continue
            
        if "failure" in filename or "malformed" in filename:
            continue
            
        with open(os.path.join(VECTORS_DIR, filename), "r") as f:
            vector = json.load(f)
            
        alg = vector["algorithm"]
        inputs = vector["inputs"]
        expected = vector["expected_outputs"]
        
        # 1. Independently compute X25519 KEM
        init_priv_bytes = binascii.unhexlify(inputs["x25519_initiator_private"])
        resp_pub_bytes = binascii.unhexlify(inputs["x25519_responder_public"])
        
        init_priv = X25519PrivateKey.from_private_bytes(init_priv_bytes)
        resp_pub = X25519PublicKey.from_public_bytes(resp_pub_bytes)
        
        x25519_shared_secret = init_priv.exchange(resp_pub)
        x25519_ciphertext = init_priv.public_key().public_bytes_raw()
        
        shared_secrets = [("x25519", x25519_shared_secret)]
        ciphertexts = [("x25519", x25519_ciphertext)]
        
        # 2. Add mocked PQC if present
        if alg in ("hybrid_standard", "hybrid_high"):
            pqc_alg = "mlkem768" if alg == "hybrid_standard" else "mlkem1024"
            pqc_ss = binascii.unhexlify(inputs[f"{pqc_alg}_shared_secret"])
            pqc_ct = binascii.unhexlify(inputs[f"{pqc_alg}_ciphertext"])
            shared_secrets.append((pqc_alg, pqc_ss))
            ciphertexts.append((pqc_alg, pqc_ct))
            
        # 3. Independently compute HKDF (IKM, info, root_key)
        ikm = b"".join(ss for _, ss in shared_secrets)
        info = _encode_info(b"cryptoflex-hybrid-kem-combiner", ciphertexts)
        
        hkdf = HKDF(
            algorithm=hashes.SHA384(),
            length=32,
            salt=None,
            info=info,
        )
        root_key = hkdf.derive(ikm)
        
        # 4. Independently encode header
        nonce = binascii.unhexlify(inputs["nonce"])
        header_bytes = _encode_header(alg, ciphertexts, nonce)
        
        # 5. Compare with expected
        assert ikm == binascii.unhexlify(expected["ikm"])
        assert info == binascii.unhexlify(expected["info_context"])
        assert root_key == binascii.unhexlify(expected["derived_root_key"])
        assert header_bytes == binascii.unhexlify(expected["header_encoding"])
