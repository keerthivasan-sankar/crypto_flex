from cryptoflex.utils import zeroize


def test_zeroize_bytearray():
    buf = bytearray(b"super_secret_private_key_bytes")
    zeroize(buf)
    assert buf == bytearray(len(buf))


def test_zeroize_memoryview():
    buf = bytearray(b"sensitive_buffer")
    mv = memoryview(buf)
    zeroize(mv)
    assert buf == bytearray(len(buf))
