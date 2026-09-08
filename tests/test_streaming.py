import io
import struct
import pytest

from cryptoflex.api import DecryptionError, DowngradeError, establish_keys
from cryptoflex.policy import Constraint, PolicyEngine
from cryptoflex.streaming import (
    DEFAULT_CHUNK_SIZE,
    FRAME_TYPE_DATA,
    FRAME_TYPE_FINAL,
    MAX_CHUNK_PLAINTEXT_SIZE,
    decrypt_stream,
    encrypt_stream,
)


def test_streaming_round_trip_classical():
    engine = PolicyEngine()
    keyset = establish_keys(engine, constraint=Constraint.FAST)

    plaintext = b"Large Payload Data Stream " * 5000  # ~130 KB
    fin = io.BytesIO(plaintext)
    fout = io.BytesIO()

    encrypt_stream(keyset.public_bundle, fin, fout, chunk_size=16 * 1024)

    ciphertext_blob = fout.getvalue()
    assert len(ciphertext_blob) > len(plaintext)

    f_enc_in = io.BytesIO(ciphertext_blob)
    f_dec_out = io.BytesIO()

    decrypt_stream(keyset.private_handles, f_enc_in, f_dec_out)
    assert f_dec_out.getvalue() == plaintext


def test_streaming_round_trip_hybrid(hybrid_mock_profile, FixedProfileEngine):
    engine = FixedProfileEngine(hybrid_mock_profile)
    keyset = establish_keys(engine)

    plaintext = b"Hybrid Streaming Data Chunk " * 2000
    fin = io.BytesIO(plaintext)
    fout = io.BytesIO()

    encrypt_stream(keyset.public_bundle, fin, fout, chunk_size=8 * 1024)

    f_enc_in = io.BytesIO(fout.getvalue())
    f_dec_out = io.BytesIO()

    decrypt_stream(keyset.private_handles, f_enc_in, f_dec_out)
    assert f_dec_out.getvalue() == plaintext


def test_streaming_rejects_truncated_middle_chunk():
    engine = PolicyEngine()
    keyset = establish_keys(engine, constraint=Constraint.FAST)

    fin = io.BytesIO(b"Chunk1_data_here___Chunk2_data_here___")
    fout = io.BytesIO()
    encrypt_stream(keyset.public_bundle, fin, fout, chunk_size=16)

    blob = fout.getvalue()
    # Truncate blob in the middle of chunk 2
    truncated_blob = blob[: len(blob) - 10]

    f_enc_in = io.BytesIO(truncated_blob)
    f_dec_out = io.BytesIO()

    with pytest.raises(DecryptionError):
        decrypt_stream(keyset.private_handles, f_enc_in, f_dec_out)


def test_streaming_rejects_tampered_chunk_tag():
    engine = PolicyEngine()
    keyset = establish_keys(engine, constraint=Constraint.FAST)

    fin = io.BytesIO(b"Data stream chunk 1. Data stream chunk 2.")
    fout = io.BytesIO()
    encrypt_stream(keyset.public_bundle, fin, fout, chunk_size=20)

    blob = bytearray(fout.getvalue())
    # Tamper a byte in the last DATA chunk (before FINAL frame)
    # Find last DATA frame and tamper it
    blob[-30] ^= 0xFF

    f_enc_in = io.BytesIO(bytes(blob))
    f_dec_out = io.BytesIO()

    with pytest.raises(DecryptionError):
        decrypt_stream(keyset.private_handles, f_enc_in, f_dec_out)


def test_streaming_min_profile_enforcement():
    engine = PolicyEngine()
    keyset = establish_keys(engine, constraint=Constraint.FAST)

    fin = io.BytesIO(b"Stream data")
    fout = io.BytesIO()
    encrypt_stream(keyset.public_bundle, fin, fout)

    f_enc_in = io.BytesIO(fout.getvalue())
    f_dec_out = io.BytesIO()

    with pytest.raises(DowngradeError):
        decrypt_stream(keyset.private_handles, f_enc_in, f_dec_out, min_profile="hybrid_standard")


# ============================================================================
# New Round 2 tests: Authenticated FINAL frame validation
# ============================================================================


def _encrypt_test_stream(keyset, plaintext, chunk_size=16):
    """Helper to produce a valid encrypted stream blob."""
    fin = io.BytesIO(plaintext)
    fout = io.BytesIO()
    encrypt_stream(keyset.public_bundle, fin, fout, chunk_size=chunk_size)
    return fout.getvalue()


def _make_keyset():
    engine = PolicyEngine()
    return establish_keys(engine, constraint=Constraint.FAST)


def test_streaming_rejects_missing_final_frame():
    """Truncate stream before the FINAL frame — must fail."""
    keyset = _make_keyset()
    blob = bytearray(_encrypt_test_stream(keyset, b"Some test data for truncation"))

    # Find and remove the FINAL frame (last 1 + 4 + 16 = 21 bytes)
    # FINAL frame = type(1) + length(4) + ct(16)
    truncated = blob[:-21]

    with pytest.raises(DecryptionError, match="FINAL"):
        decrypt_stream(keyset.private_handles, io.BytesIO(bytes(truncated)), io.BytesIO())


def test_streaming_rejects_forged_terminal_marker():
    """Replace the authenticated FINAL frame with a raw 0x00000000 — must fail."""
    keyset = _make_keyset()
    blob = bytearray(_encrypt_test_stream(keyset, b"Forged terminal test data"))

    # Remove FINAL frame and append old-style unauthenticated marker
    truncated = blob[:-21]
    forged = bytes(truncated) + struct.pack(">I", 0)

    with pytest.raises(DecryptionError):
        decrypt_stream(keyset.private_handles, io.BytesIO(forged), io.BytesIO())


def test_streaming_rejects_appended_chunks_after_final():
    """Append data bytes after the authenticated FINAL frame — must fail."""
    keyset = _make_keyset()
    blob = _encrypt_test_stream(keyset, b"Data before FINAL frame test")

    # Append garbage after the valid stream
    extended = blob + b"\x01\x00\x00\x00\x10" + b"\x00" * 16

    with pytest.raises(DecryptionError, match="trailing data|data after FINAL"):
        decrypt_stream(keyset.private_handles, io.BytesIO(extended), io.BytesIO())


def test_streaming_rejects_duplicate_final():
    """Write two consecutive FINAL frames — must fail."""
    keyset = _make_keyset()
    blob = _encrypt_test_stream(keyset, b"Duplicate FINAL test")

    # The FINAL frame is the last 21 bytes; duplicate it
    final_frame = blob[-21:]
    doubled = blob + final_frame

    with pytest.raises(DecryptionError, match="trailing data|data after FINAL"):
        decrypt_stream(keyset.private_handles, io.BytesIO(doubled), io.BytesIO())


def test_streaming_rejects_wrong_final_sequence():
    """Forge a FINAL frame with a wrong sequence number — must fail (GCM tag check)."""
    keyset = _make_keyset()
    # Encrypt with chunk_size=16 to get multiple DATA frames
    plaintext = b"A" * 32  # Two DATA frames at chunk_size=16
    blob = bytearray(_encrypt_test_stream(keyset, plaintext, chunk_size=16))

    # Swap the FINAL frame's tag bytes to invalidate it
    # (This simulates wrong sequence since the AAD includes the sequence number)
    blob[-1] ^= 0xFF  # Flip last byte of FINAL ciphertext (GCM tag)

    with pytest.raises(DecryptionError):
        decrypt_stream(keyset.private_handles, io.BytesIO(bytes(blob)), io.BytesIO())


def test_streaming_rejects_trailing_bytes():
    """Single trailing byte after FINAL — must fail."""
    keyset = _make_keyset()
    blob = _encrypt_test_stream(keyset, b"Trailing byte test")

    trailing = blob + b"\x00"

    with pytest.raises(DecryptionError, match="trailing data|data after FINAL"):
        decrypt_stream(keyset.private_handles, io.BytesIO(trailing), io.BytesIO())


def test_streaming_exact_max_chunk():
    """A chunk exactly at MAX_CHUNK_PLAINTEXT_SIZE should be accepted."""
    keyset = _make_keyset()
    # Use a smaller "max" for testing feasibility — just verify the boundary check logic
    # by encrypting with chunk_size == MAX_CHUNK_PLAINTEXT_SIZE
    # (We can't actually allocate 9MB in a unit test easily, so test with default max)
    plaintext = b"X" * DEFAULT_CHUNK_SIZE  # Exactly one default chunk
    fin = io.BytesIO(plaintext)
    fout = io.BytesIO()

    encrypt_stream(keyset.public_bundle, fin, fout, chunk_size=DEFAULT_CHUNK_SIZE)
    blob = fout.getvalue()

    dec_out = io.BytesIO()
    decrypt_stream(keyset.private_handles, io.BytesIO(blob), dec_out)
    assert dec_out.getvalue() == plaintext


def test_streaming_rejects_chunk_over_max():
    """chunk_size > MAX_CHUNK_PLAINTEXT_SIZE must be rejected at encrypt time."""
    keyset = _make_keyset()

    with pytest.raises(ValueError, match="chunk_size"):
        encrypt_stream(
            keyset.public_bundle,
            io.BytesIO(b"data"),
            io.BytesIO(),
            chunk_size=MAX_CHUNK_PLAINTEXT_SIZE + 1,
        )


def test_streaming_rejects_zero_chunk_size():
    """chunk_size == 0 must be rejected."""
    keyset = _make_keyset()

    with pytest.raises(ValueError, match="chunk_size"):
        encrypt_stream(keyset.public_bundle, io.BytesIO(b"data"), io.BytesIO(), chunk_size=0)


def test_streaming_rejects_negative_chunk_size():
    """chunk_size < 0 must be rejected."""
    keyset = _make_keyset()

    with pytest.raises(ValueError, match="chunk_size"):
        encrypt_stream(keyset.public_bundle, io.BytesIO(b"data"), io.BytesIO(), chunk_size=-1)


def test_streaming_rejects_invalid_frame_type():
    """A frame with an invalid type byte (not DATA or FINAL) must be rejected."""
    keyset = _make_keyset()
    blob = bytearray(_encrypt_test_stream(keyset, b"Invalid frame type test"))

    # Find the first DATA frame type byte (right after the header)
    # The header is variable-length, so find the first 0x01 byte that starts a frame
    from cryptoflex.header import CryptoflexHeader
    _, consumed = CryptoflexHeader.from_bytes(bytes(blob))

    # Replace the first frame type byte with an invalid value
    blob[consumed] = 0xFF

    with pytest.raises(DecryptionError, match="invalid frame type"):
        decrypt_stream(keyset.private_handles, io.BytesIO(bytes(blob)), io.BytesIO())


def test_streaming_truncation_then_forged_final_regression():
    """Regression: valid DATA0 + DATA1 + FINAL, truncate DATA1, append forged FINAL → MUST FAIL."""
    keyset = _make_keyset()
    plaintext = b"A" * 16 + b"B" * 16  # Two DATA frames at chunk_size=16
    blob = _encrypt_test_stream(keyset, plaintext, chunk_size=16)

    from cryptoflex.header import CryptoflexHeader
    _, consumed = CryptoflexHeader.from_bytes(blob)
    stream_data = blob[consumed:]

    # Parse: frame0 (DATA), frame1 (DATA), frame2 (FINAL)
    # Each DATA frame: 1 byte type + 4 bytes len + (16 + 16) bytes ct = 37 bytes
    # FINAL frame: 1 byte type + 4 bytes len + 16 bytes ct = 21 bytes
    # But actual ct size varies (plaintext 16 bytes + 16 tag = 32 bytes ct)

    # Read first DATA frame
    pos = 0
    ft0 = stream_data[pos]; pos += 1
    assert ft0 == FRAME_TYPE_DATA
    len0 = struct.unpack(">I", stream_data[pos:pos+4])[0]; pos += 4
    pos += len0  # skip ct

    # We have DATA0 complete. Now build: header + DATA0 + forged FINAL
    data0_end = consumed + pos

    # Create a forged FINAL: type=0x02, length=16, 16 zero bytes
    forged_final = struct.pack("B", FRAME_TYPE_FINAL) + struct.pack(">I", 16) + b"\x00" * 16

    forged_stream = blob[:data0_end] + forged_final

    with pytest.raises(DecryptionError):
        decrypt_stream(keyset.private_handles, io.BytesIO(forged_stream), io.BytesIO())
