"""
cryptoflex.streaming
======================

Streaming AEAD Encryption and Decryption for Large Files.

Security & Design Rationale
----------------------------
For large files (multi-gigabyte payloads), buffering the entire file into
RAM at once is impractical.  This module implements chunked AEAD using
AES-256-GCM without memory overhead.

To prevent chunk-reordering, truncation, or insertion attacks:
  - Each chunk is encrypted using a unique 12-byte nonce formed by
    concatenating the header's 8-byte base nonce with a 4-byte big-endian
    chunk sequence counter `i`.
  - The AEAD Associated Data (AAD) for chunk `i` binds the header bytes AND
    the 4-byte big-endian chunk sequence counter `i`.
  - The final chunk is explicitly marked, or stream ends with a zero-length
    terminal chunk indicator, ensuring truncation is detected.

Wire Format for Stream Payload (following the CryptoflexHeader):
  For each chunk:
    4 bytes  chunk_payload_length (big-endian integer)
    N bytes  AES-256-GCM ciphertext + 16-byte tag
  Terminal marker:
    4 bytes  0x00000000 (0 length indicates clean end-of-stream)
"""

from __future__ import annotations

import struct
from typing import BinaryIO

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .api import PublicBundle, derive_root_key
from .errors import DecryptionError, DowngradeError
from .header import CryptoflexHeader, HeaderParseError
from .profiles import get_profile

DEFAULT_CHUNK_SIZE = 64 * 1024  # 64 KB per chunk
MAX_CHUNK_SIZE = 9 * 1024 * 1024  # 9 MB — must match decrypt_stream sanity limit
MAX_HEADER_SIZE = 64 * 1024  # 64 KB — enough for any realistic future profile


def _derive_chunk_nonce(base_nonce: bytes, sequence_number: int) -> bytes:
    """Create a 12-byte per-chunk nonce by taking the first 8 bytes of the
    base nonce and appending the 4-byte big-endian sequence number."""
    if len(base_nonce) != 12:
        raise ValueError("base_nonce must be exactly 12 bytes")
    if sequence_number > 0xFFFFFFFF:
        raise OverflowError("stream chunk limit exceeded (max 4,294,967,295 chunks)")
    return base_nonce[:8] + struct.pack(">I", sequence_number)


def _derive_chunk_aad(header_bytes: bytes, sequence_number: int) -> bytes:
    """Bind the header bytes and chunk sequence number into AEAD AAD."""
    return header_bytes + struct.pack(">I", sequence_number)


def encrypt_stream(
    bundle: PublicBundle,
    input_stream: BinaryIO,
    output_stream: BinaryIO,
    chunk_size: int = DEFAULT_CHUNK_SIZE,
) -> None:
    """Encrypt a binary input stream into an output stream chunk-by-chunk.

    Writes the serialized header first, followed by chunk length headers and
    AEAD encrypted blocks.
    """
    derived = derive_root_key(bundle)
    header_bytes = derived.header.to_bytes()
    base_nonce = derived.header.nonce
    if base_nonce is None:  # v2 headers always have a nonce
        raise ValueError("derive_root_key() produced a v1 header with no nonce — cannot stream-encrypt")
    if chunk_size > MAX_CHUNK_SIZE:
        raise ValueError(f"chunk_size {chunk_size} exceeds MAX_CHUNK_SIZE {MAX_CHUNK_SIZE}; reduce to ensure decryptability")

    output_stream.write(header_bytes)
    aesgcm = AESGCM(derived.root_key)

    # Eagerly drop the derived root key object; aesgcm holds the key internally.
    del derived

    sequence_number = 0
    while True:
        chunk = input_stream.read(chunk_size)
        if not chunk:
            break

        nonce = _derive_chunk_nonce(base_nonce, sequence_number)
        aad = _derive_chunk_aad(header_bytes, sequence_number)

        ct_with_tag = aesgcm.encrypt(nonce, chunk, aad)
        output_stream.write(struct.pack(">I", len(ct_with_tag)))
        output_stream.write(ct_with_tag)
        sequence_number += 1

    # Write terminal marker (0-length chunk)
    output_stream.write(struct.pack(">I", 0))

    del aesgcm  # drop AEAD key reference after stream is fully written


def decrypt_stream(
    private_handles: list[object],
    input_stream: BinaryIO,
    output_stream: BinaryIO,
    *,
    min_profile: str | None = None,
) -> None:
    """Decrypt a chunked stream produced by encrypt_stream.

    Validates header, min_profile, per-chunk AEAD tags, and sequence order.
    Raises DecryptionError or DowngradeError on failure.
    """
    # Read initial bytes to parse header
    initial_bytes = input_stream.read(MAX_HEADER_SIZE)
    if not initial_bytes:
        raise DecryptionError("decryption failed: empty stream")

    try:
        header, consumed = CryptoflexHeader.from_bytes(initial_bytes)
    except HeaderParseError:
        raise DecryptionError("decryption failed: invalid header")

    header_bytes = initial_bytes[:consumed]
    unconsumed_initial = initial_bytes[consumed:]

    # Downgrade check
    if min_profile is not None:
        try:
            header_profile = get_profile(header.profile_id)
            min_prof = get_profile(min_profile)
        except ValueError:
            raise DecryptionError("decryption failed")
        if header_profile.strength_level < min_prof.strength_level:
            raise DowngradeError(
                f"header profile '{header.profile_id}' "
                f"(strength={header_profile.strength_level}) is weaker than "
                f"minimum accepted profile '{min_profile}' "
                f"(strength={min_prof.strength_level})"
            )

    if header.nonce is None:
        raise DecryptionError("decryption failed: v1 header not supported in streaming mode")

    try:
        profile = get_profile(header.profile_id)
        from .api import _recover_root_key_internal

        root_key = _recover_root_key_internal(private_handles, header, profile)
        aesgcm = AESGCM(root_key)

        # Eagerly drop root key reference; aesgcm holds the key internally.
        del root_key
    except (DowngradeError, DecryptionError):
        raise
    except Exception:
        raise DecryptionError("decryption failed")

    # Helper buffer for stream reading
    class StreamReader:
        def __init__(self, initial: bytes, stream: BinaryIO):
            self.buf = bytearray(initial)
            self.stream = stream

        def read_exact(self, n: int) -> bytes:
            while len(self.buf) < n:
                more = self.stream.read(n - len(self.buf) + 4096)
                if not more:
                    break
                self.buf.extend(more)

            if len(self.buf) < n:
                raise DecryptionError("decryption failed: truncated chunk")

            res = bytes(self.buf[:n])
            del self.buf[:n]
            return res

        def has_data(self) -> bool:
            return len(self.buf) > 0

    reader = StreamReader(unconsumed_initial, input_stream)
    sequence_number = 0

    try:
        while True:
            length_bytes = reader.read_exact(4)
            (ct_len,) = struct.unpack(">I", length_bytes)

            if ct_len == 0:
                # Terminal marker reached
                break

            if ct_len > MAX_CHUNK_SIZE:  # matches encrypt_stream's cap
                raise DecryptionError("decryption failed: chunk size exceeds limit")

            ct_with_tag = reader.read_exact(ct_len)
            nonce = _derive_chunk_nonce(header.nonce, sequence_number)
            aad = _derive_chunk_aad(header_bytes, sequence_number)

            plaintext = aesgcm.decrypt(nonce, ct_with_tag, aad)
            output_stream.write(plaintext)
            sequence_number += 1
    except (DowngradeError, DecryptionError):
        raise
    except Exception:
        raise DecryptionError("decryption failed")
