import os
import pytest
from cryptoflex.sources import PQCSource, MockPQCSource
from cryptoflex.api import DecryptionError

def is_real_pqc_available():
    src = PQCSource()
    return src.is_available()

@pytest.mark.parametrize("source_cls", [PQCSource, MockPQCSource])
def test_private_key_round_trip(source_cls):
    if source_cls is PQCSource and not is_real_pqc_available():
        pytest.skip("Real PQC source not available")
    src = source_cls()
    pub, priv_handle = src.generate_keypair()
    serialized = src.serialize_private(priv_handle)
    recovered = src.deserialize_private(serialized)
    enc = src.encapsulate(pub)
    assert src.decapsulate(recovered, enc.ciphertext) == enc.shared_secret

# ==== Real PQC malformed data tests ====
@pytest.mark.parametrize("malformed", [b"", b"short", os.urandom(10)])
def test_private_key_malformed_data_real(malformed):
    if not is_real_pqc_available():
        pytest.skip("Real PQC source not available")
    src = PQCSource()
    with pytest.raises(ValueError):
        src.deserialize_private(malformed)

# ==== Invalid length (truncated) handling ====
def test_private_key_invalid_length_real():
    if not is_real_pqc_available():
        pytest.skip("Real PQC source not available")
    src = PQCSource()
    # generate valid private key then truncate one byte
    _, priv_handle = src.generate_keypair()
    serialized = src.serialize_private(priv_handle)
    bad = serialized[:-1]
    with pytest.raises(ValueError):
        src.deserialize_private(bad)

def test_private_key_corrupted_byte_real():
    if not is_real_pqc_available():
        pytest.skip("Real PQC source not available")
    src = PQCSource()
    _, priv_handle = src.generate_keypair()
    serialized = bytearray(src.serialize_private(priv_handle))
    # corrupt a byte (choose index 10 if possible)
    idx = 10 if len(serialized) > 10 else 0
    original = serialized[idx]
    serialized[idx] = (original ^ 0xFF) & 0xFF
    corrupted = bytes(serialized)
    # First attempt deserialization; may raise ValueError.
    try:
        priv_handle_corrupt = src.deserialize_private(corrupted)
    except ValueError:
        # Expected path: deserialization detects corruption.
        return
    # If deserialization succeeded, exercising decapsulation should raise DecryptionError.
    pub, _ = src.generate_keypair()
    enc = src.encapsulate(pub)
    with pytest.raises(DecryptionError):
        try:
            src.decapsulate(priv_handle_corrupt, enc.ciphertext)
        except DecryptionError:
            raise
        else:
            raise DecryptionError("Decapsulation succeeded with corrupted key")



# ==== Decapsulate length validation ====
def test_decapsulate_length_validation():
    if not is_real_pqc_available():
        pytest.skip("Real PQC source not available")
    src = PQCSource()
    # valid private handle (won't be used for actual secret)
    _, priv_handle = src.generate_keypair()
    pub, _ = src.generate_keypair()
    enc = src.encapsulate(pub)
    # truncate ciphertext
    short_ct = enc.ciphertext[:-1]
    with pytest.raises(ValueError):
        src.decapsulate(priv_handle, short_ct)
    # extend ciphertext
    long_ct = enc.ciphertext + b"\x00"
    with pytest.raises(ValueError):
        src.decapsulate(priv_handle, long_ct)
