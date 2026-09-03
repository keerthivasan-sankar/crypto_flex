import io
import pytest

from cryptoflex.api import DecryptionError, DowngradeError, establish_keys
from cryptoflex.policy import Constraint, PolicyEngine
from cryptoflex.streaming import decrypt_stream, encrypt_stream


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
    # Tamper a byte in the last chunk
    blob[-5] ^= 0xFF

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
