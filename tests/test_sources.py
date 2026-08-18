from cryptoflex.sources import (
    ClassicalSource,
    MockPQCSource,
    PQCSource,
    SourceUnavailableError,
)


def test_classical_source_round_trip():
    source = ClassicalSource()
    assert source.is_available() is True

    pub, priv = source.generate_keypair()
    enc = source.encapsulate(pub)
    recovered = source.decapsulate(priv, enc.ciphertext)

    assert recovered == enc.shared_secret


def test_classical_source_different_keypairs_give_different_secrets():
    source = ClassicalSource()
    pub1, _ = source.generate_keypair()
    pub2, _ = source.generate_keypair()

    enc1 = source.encapsulate(pub1)
    enc2 = source.encapsulate(pub2)

    assert enc1.shared_secret != enc2.shared_secret


def test_mock_pqc_source_round_trip():
    source = MockPQCSource()
    assert source.is_available() is True

    pub, priv = source.generate_keypair()
    enc = source.encapsulate(pub)
    recovered = source.decapsulate(priv, enc.ciphertext)

    assert recovered == enc.shared_secret


def test_pqc_source_unavailable_raises_not_crashes():
    """If liboqs isn't installed/built, PQCSource must report unavailable
    and raise a clear, catchable error - never crash the process or
    silently return garbage key material."""
    source = PQCSource("ML-KEM-768")

    if source.is_available():
        # if liboqs happens to be built in this environment, just do the
        # real round trip instead
        pub, priv = source.generate_keypair()
        enc = source.encapsulate(pub)
        recovered = source.decapsulate(priv, enc.ciphertext)
        assert recovered == enc.shared_secret
    else:
        try:
            source.generate_keypair()
            assert False, "expected SourceUnavailableError"
        except SourceUnavailableError:
            pass
