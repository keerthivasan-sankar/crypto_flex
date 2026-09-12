import os
import pytest
from cryptoflex.sources import PQCSource, MockPQCSource

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

@pytest.mark.parametrize("malformed", [b"", b"short", os.urandom(10)])
def test_private_key_malformed_data(malformed):
    # For MockPQCSource, deserialize simply returns the data unchanged
    src = MockPQCSource()
    handle = src.deserialize_private(malformed)
    assert handle == malformed

def test_private_key_invalid_length_real():
    if not is_real_pqc_available():
        pytest.skip("Real PQC source not available")
    src = PQCSource()
    # Obtain a valid serialized key then truncate one byte
    _, priv_handle = src.generate_keypair()
    serialized = src.serialize_private(priv_handle)
    bad = serialized[:-1]
    with pytest.raises(Exception):
        src.deserialize_private(bad)
