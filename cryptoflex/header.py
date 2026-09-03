"""
cryptoflex.header
====================

Versioned header format for anything encrypted with a cryptoflex-derived
key.  This is the piece that makes migration actually work: a file
encrypted today under ``hybrid_standard`` must still be decryptable in
five years even after the PolicyEngine's default has moved on to
something else - because the header records exactly which profile and
component ciphertexts were used, independent of current policy.

Wire format v2 (all integers big-endian):
  4 bytes   magic           b"CFLX"
  1 byte    version         format version (2)
  1 byte    profile_id_len
  N bytes   profile_id      utf-8, e.g. b"hybrid_standard"
  1 byte    num_components
  for each component:
    1 byte    alg_id_len
    N bytes   alg_id          utf-8, e.g. b"mlkem768"
    2 bytes   ciphertext_len
    N bytes   ciphertext
  12 bytes  nonce           AES-256-GCM nonce

Design change (Discussion #2534 feedback):
  "The version, profile/algorithm identifiers, both encapsulated keys,
  nonces, and any policy metadata that affects decryption should be
  authenticated as AEAD associated data."

The header is designed so that its serialized byte representation can be
passed directly as AAD to AES-256-GCM.  The nonce is embedded in the
header so it is also authenticated.

Backward compatibility:
  v1 headers (no nonce) can still be parsed; the nonce field will be
  None.  The high-level decrypt() API rejects v1 headers since they
  cannot be AEAD-authenticated, but the low-level recover_root_key()
  still accepts them for migration scenarios.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from typing import Optional

MAGIC = b"CFLX"
FORMAT_VERSION = 2      # current version this library produces
SUPPORTED_VERSIONS = {1, 2}  # versions this library can parse
NONCE_LEN = 12          # AES-256-GCM nonce length


class HeaderParseError(ValueError):
    pass


@dataclass(frozen=True)
class CryptoflexHeader:
    profile_id: str
    components: list[tuple[str, bytes]]  # (algorithm_id, ciphertext)
    nonce: Optional[bytes] = None        # 12 bytes; None for v1 headers
    version: int = FORMAT_VERSION        # header format version

    def to_bytes(self) -> bytes:
        out = bytearray()
        out += MAGIC
        out += struct.pack("B", self.version)

        profile_bytes = self.profile_id.encode("utf-8")
        if len(profile_bytes) > 255:
            raise ValueError("profile_id too long to encode")
        out += struct.pack("B", len(profile_bytes))
        out += profile_bytes

        if len(self.components) > 255:
            raise ValueError("too many components to encode")
        out += struct.pack("B", len(self.components))

        for alg_id, ciphertext in self.components:
            alg_bytes = alg_id.encode("utf-8")
            if len(alg_bytes) > 255:
                raise ValueError(f"algorithm_id '{alg_id}' too long to encode")
            if len(ciphertext) > 65535:
                raise ValueError(f"ciphertext for '{alg_id}' too long to encode")
            out += struct.pack("B", len(alg_bytes))
            out += alg_bytes
            out += struct.pack(">H", len(ciphertext))
            out += ciphertext

        # v2+: append nonce
        if self.version >= 2:
            if self.nonce is None or len(self.nonce) != NONCE_LEN:
                raise ValueError(
                    f"v2 header requires a {NONCE_LEN}-byte nonce, "
                    f"got {len(self.nonce) if self.nonce else 'None'}"
                )
            out += self.nonce

        return bytes(out)

    @staticmethod
    def from_bytes(data: bytes) -> tuple["CryptoflexHeader", int]:
        """Parse a header from the start of ``data``.  Returns (header,
        bytes_consumed) so the caller can slice off the rest of the
        payload (e.g. the AEAD ciphertext) that follows.

        Any malformed or truncated input - including input that runs out
        of bytes mid-field - is guaranteed to raise HeaderParseError, and
        only HeaderParseError.  Truncated/corrupted data is an expected,
        everyday failure mode (a partially-written file, a network glitch,
        or a hostile input), not a programming error, so callers should
        only ever need to catch this one exception type here rather than
        also handling struct.error/IndexError/UnicodeDecodeError from
        this function's internals.
        """
        try:
            return CryptoflexHeader._parse(data)
        except HeaderParseError:
            raise
        except (IndexError, struct.error, UnicodeDecodeError) as e:
            raise HeaderParseError(
                f"malformed or truncated cryptoflex header: {e}"
            ) from e

    @staticmethod
    def _parse(data: bytes) -> tuple["CryptoflexHeader", int]:
        if len(data) < 6 or data[:4] != MAGIC:
            raise HeaderParseError("missing or invalid cryptoflex header magic")

        offset = 4
        version = data[offset]
        offset += 1

        if version not in SUPPORTED_VERSIONS:
            raise HeaderParseError(
                f"unsupported cryptoflex header version {version}; "
                f"this library supports versions {sorted(SUPPORTED_VERSIONS)}. "
                f"A newer/older library version may be required to read this file."
            )

        profile_id_len = data[offset]
        offset += 1
        if offset + profile_id_len > len(data):
            raise HeaderParseError("truncated profile_id field")
        profile_id = data[offset : offset + profile_id_len].decode("utf-8")
        offset += profile_id_len

        if offset >= len(data):
            raise HeaderParseError("truncated header: missing num_components")
        num_components = data[offset]
        offset += 1

        components: list[tuple[str, bytes]] = []
        for _ in range(num_components):
            if offset >= len(data):
                raise HeaderParseError("truncated algorithm_id length field")
            alg_len = data[offset]
            offset += 1
            if offset + alg_len > len(data):
                raise HeaderParseError("truncated algorithm_id field")
            alg_id = data[offset : offset + alg_len].decode("utf-8")
            offset += alg_len

            if offset + 2 > len(data):
                raise HeaderParseError("truncated ciphertext length field")
            (ct_len,) = struct.unpack(">H", data[offset : offset + 2])
            offset += 2
            if offset + ct_len > len(data):
                raise HeaderParseError("truncated ciphertext field")
            ciphertext = data[offset : offset + ct_len]
            offset += ct_len

            components.append((alg_id, ciphertext))

        # v2+: read nonce
        nonce: Optional[bytes] = None
        if version >= 2:
            if offset + NONCE_LEN > len(data):
                raise HeaderParseError("truncated nonce field")
            nonce = data[offset : offset + NONCE_LEN]
            offset += NONCE_LEN

        return (
            CryptoflexHeader(
                profile_id=profile_id,
                components=components,
                nonce=nonce,
                version=version,
            ),
            offset,
        )
