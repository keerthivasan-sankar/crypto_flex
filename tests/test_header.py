import pytest

from cryptoflex.header import CryptoflexHeader, HeaderParseError



def test_header_round_trip_single_component():
    header = CryptoflexHeader(
        profile_id="classical_only",
        components=[("x25519", b"\x01\x02\x03" * 10)],
        nonce=b"\x00" * 12,
    )
    data = header.to_bytes()
    parsed, consumed = CryptoflexHeader.from_bytes(data)

    assert parsed == header
    assert consumed == len(data)


def test_header_round_trip_multi_component():
    header = CryptoflexHeader(
        profile_id="hybrid_standard",
        components=[
            ("x25519", b"\xaa" * 32),
            ("mlkem768", b"\xbb" * 1088),  # realistic ML-KEM-768 ciphertext size
        ],
        nonce=b"\x12" * 12,
    )
    data = header.to_bytes()
    parsed, consumed = CryptoflexHeader.from_bytes(data)

    assert parsed == header
    assert consumed == len(data)


def test_v1_header_backwards_compatible_parsing():
    """Verify v1 format bytes parse cleanly with nonce=None and version=1."""
    v1_header = CryptoflexHeader(
        profile_id="classical_only",
        components=[("x25519", b"\x00" * 32)],
        version=1,
    )
    data = v1_header.to_bytes()
    parsed, consumed = CryptoflexHeader.from_bytes(data)

    assert parsed.version == 1
    assert parsed.nonce is None
    assert parsed.profile_id == "classical_only"
    assert consumed == len(data)


def test_header_followed_by_payload_only_consumes_its_own_bytes():
    header = CryptoflexHeader(
        profile_id="classical_only",
        components=[("x25519", b"\x00" * 32)],
        nonce=b"\xff" * 12,
    )
    payload = b"THIS-IS-THE-ENCRYPTED-FILE-PAYLOAD"
    blob = header.to_bytes() + payload

    parsed, consumed = CryptoflexHeader.from_bytes(blob)
    assert parsed == header
    assert blob[consumed:] == payload


def test_rejects_bad_magic():
    with pytest.raises(HeaderParseError):
        CryptoflexHeader.from_bytes(b"NOPE" + b"\x00" * 10)


def test_rejects_unsupported_version():
    header = CryptoflexHeader(
        profile_id="classical_only",
        components=[("x25519", b"\x00" * 32)],
        nonce=b"\x00" * 12,
    )
    data = bytearray(header.to_bytes())
    # corrupt the version byte (offset 4) to something unsupported
    data[4] = 99
    with pytest.raises(HeaderParseError):
        CryptoflexHeader.from_bytes(bytes(data))
