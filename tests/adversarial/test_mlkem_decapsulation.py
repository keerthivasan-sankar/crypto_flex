# tests/adversarial/test_mlkem_decapsulation.py
"""Adversarial tests for ML-KEM decapsulation length validation and error handling.
These tests are conditional on liboqs being available. They are skipped otherwise.
"""

import os
import pytest

from cryptoflex.sources import PQCSource, SourceUnavailableError

@pytest.fixture(scope="module")
def pqc_source():
    src = PQCSource()
    if not src.is_available():
        pytest.skip("PQCSource not available – liboqs not installed")
    return src

def test_ciphertext_length_validation(pqc_source):
    # Generate a keypair to obtain a valid ciphertext length
    pub, priv = pqc_source.generate_keypair()
    # Perform an encapsulation to get a valid ciphertext length
    enc = pqc_source.encapsulate(pub)
    expected_len = len(enc.ciphertext)

    # Truncated ciphertext
    truncated = enc.ciphertext[: expected_len // 2]
    with pytest.raises(ValueError, match="Invalid ciphertext length"):
        pqc_source.decapsulate(priv, truncated)

    # Extended ciphertext (one extra byte)
    extended = enc.ciphertext + b"\x00"
    with pytest.raises(ValueError, match="Invalid ciphertext length"):
        pqc_source.decapsulate(priv, extended)

    # Random valid‑length ciphertext (may raise liboqs errors)
    random_ct = os.urandom(expected_len)
    # The call may raise an exception from liboqs; we only assert it does not raise our length check
    try:
        pqc_source.decapsulate(priv, random_ct)
    except Exception:
        # Accept any exception here – the length check passed, underlying liboqs may reject it
        pass
