import pytest

from cryptoflex.header import CryptoflexHeader, HeaderParseError



def test_cross_version_v1_header_fixture_decryption():
    """Verify pre-computed v1 header bytes (produced by cryptoflex v0.1.0) can be parsed and used with recover_root_key."""
    # Wire format for v1 header:
    # magic: b"CFLX"
    # version: 1
    # profile_id_len: 14 (b"classical_only")
    # profile_id: b"classical_only"
    # num_components: 1
    # alg_id_len: 6 (b"x25519")
    # alg_id: b"x25519"
    # ciphertext_len: 32
    # ciphertext: 32 bytes of 0x01
    v1_raw = (
        b"CFLX\x01"
        b"\x0eclassical_only"
        b"\x01"
        b"\x06x25519"
        b"\x00\x20" + (b"\x01" * 32)
    )

    header, consumed = CryptoflexHeader.from_bytes(v1_raw)
    assert header.version == 1
    assert header.nonce is None
    assert header.profile_id == "classical_only"
    assert len(header.components) == 1
    assert consumed == len(v1_raw)


def test_unknown_header_version_rejected():
    v99_raw = b"CFLX\x63\x0eclassical_only\x01\x06x25519\x00\x20" + (b"\x01" * 32)
    with pytest.raises(HeaderParseError, match="unsupported cryptoflex header version 99"):
        CryptoflexHeader.from_bytes(v99_raw)
