from hypothesis import given, settings
from hypothesis import strategies as st

from cryptoflex.header import CryptoflexHeader, HeaderParseError


@settings(max_examples=200)
@given(st.binary(min_size=0, max_size=512))
def test_fuzz_header_parsing_never_crashes_unhandled(data: bytes):
    """Property-based fuzzing test: CryptoflexHeader.from_bytes must ONLY
    ever raise HeaderParseError or return a valid (header, consumed) tuple.
    No unhandled exceptions (KeyError, IndexError, struct.error, etc.) may escape.
    """
    try:
        header, consumed = CryptoflexHeader.from_bytes(data)
        assert 0 <= consumed <= len(data)
        assert header.version in {1, 2}
    except HeaderParseError:
        pass  # Expected and handled failure mode
