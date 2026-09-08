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
    import struct
    data = (
        b"CFLX" +
        b"\x01" +
        struct.pack("B", len("classical_only")) +
        b"classical_only" +
        b"\x01" +
        struct.pack("B", len("x25519")) +
        b"x25519" +
        struct.pack(">H", 32) +
        (b"\x00" * 32)
    )
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


# ============================================================================
# Semantic validation tests
# ============================================================================

def _make_v2_bytes(profile_id: str, components: list, nonce: bytes) -> bytes:
    """Build raw v2 header bytes for semantic validation testing."""
    import struct
    out = bytearray()
    out += b"CFLX"
    out += b"\x02"
    pid_bytes = profile_id.encode("utf-8")
    out += struct.pack("B", len(pid_bytes))
    out += pid_bytes
    out += struct.pack("B", len(components))
    for alg_id, ct in components:
        alg_bytes = alg_id.encode("utf-8")
        out += struct.pack("B", len(alg_bytes))
        out += alg_bytes
        out += struct.pack(">H", len(ct))
        out += ct
    out += nonce
    return bytes(out)


def test_rejects_empty_profile_id():
    """An empty profile_id must be rejected with HeaderParseError."""
    data = _make_v2_bytes("", [("x25519", b"\x00" * 32)], b"\x00" * 12)
    with pytest.raises(HeaderParseError, match="empty profile_id"):
        CryptoflexHeader.from_bytes(data)


def test_rejects_zero_components():
    """A header with zero components must be rejected."""
    import struct
    out = bytearray()
    out += b"CFLX"
    out += b"\x02"
    pid = b"classical_only"
    out += struct.pack("B", len(pid))
    out += pid
    out += struct.pack("B", 0)  # zero components
    out += b"\x00" * 12  # nonce
    with pytest.raises(HeaderParseError, match="zero components"):
        CryptoflexHeader.from_bytes(bytes(out))


def test_rejects_empty_algorithm_id():
    """A component with an empty algorithm ID must be rejected."""
    import struct
    out = bytearray()
    out += b"CFLX"
    out += b"\x02"
    pid = b"classical_only"
    out += struct.pack("B", len(pid))
    out += pid
    out += struct.pack("B", 1)  # 1 component
    out += struct.pack("B", 0)  # empty alg_id
    out += struct.pack(">H", 32)
    out += b"\x00" * 32
    out += b"\x00" * 12  # nonce
    with pytest.raises(HeaderParseError, match="empty algorithm_id"):
        CryptoflexHeader.from_bytes(bytes(out))


def test_rejects_duplicate_algorithm_ids():
    """A header with duplicate algorithm IDs must be rejected."""
    data = _make_v2_bytes(
        "classical_only",
        [("x25519", b"\x00" * 32), ("x25519", b"\xff" * 32)],
        b"\x00" * 12,
    )
    with pytest.raises(HeaderParseError, match="duplicate algorithm_id"):
        CryptoflexHeader.from_bytes(data)


def test_truncation_at_every_offset():
    """Truncating a valid header at every byte offset must raise HeaderParseError."""
    header = CryptoflexHeader(
        profile_id="classical_only",
        components=[("x25519", b"\xAB" * 32)],
        nonce=b"\x12" * 12,
    )
    data = header.to_bytes()
    for cutoff in range(len(data)):
        truncated = data[:cutoff]
        with pytest.raises(HeaderParseError):
            CryptoflexHeader.from_bytes(truncated)


def test_random_bytes_raise_header_parse_error():
    """Arbitrary random binary input must raise HeaderParseError, not crash."""
    import os
    for _ in range(20):
        garbage = os.urandom(64)
        try:
            CryptoflexHeader.from_bytes(garbage)
        except HeaderParseError:
            pass  # expected
        except Exception as exc:
            raise AssertionError(
                f"from_bytes raised unexpected {type(exc).__name__}: {exc} "
                f"for input {garbage.hex()!r}"
            ) from exc


def test_rejects_malformed_utf8_profile_id():
    """Invalid UTF-8 bytes in profile_id must raise HeaderParseError."""
    import struct
    out = bytearray()
    out += b"CFLX"
    out += b"\x02"
    bad_utf8 = b"\x80\x81\x82\x83"  # invalid UTF-8
    out += struct.pack("B", len(bad_utf8))
    out += bad_utf8
    out += struct.pack("B", 1)
    alg = b"x25519"
    out += struct.pack("B", len(alg))
    out += alg
    out += struct.pack(">H", 32)
    out += b"\x00" * 32
    out += b"\x00" * 12
    with pytest.raises(HeaderParseError):
        CryptoflexHeader.from_bytes(bytes(out))
