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


def test_zeroize_readonly_memoryview():
    ro_mv = memoryview(b"readonly_bytes")
    zeroize(ro_mv)  # Should safely do nothing without raising an exception
    assert ro_mv.tobytes() == b"readonly_bytes"
