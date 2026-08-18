"""
cryptoflex.header
====================

Versioned header format for anything encrypted with a cryptoflex-derived
key. This is the piece that makes migration actually work: a file
encrypted today under `hybrid_standard` must still be decryptable in five
years even after the PolicyEngine's default has moved on to something
else - because the header records exactly which profile and component
ciphertexts were used, independent of current policy.

Wire format (all integers big-endian):
  4 bytes   magic       b"CFLX"
  1 byte    version     format version (currently 1)
  1 byte    profile_id_len
  N bytes   profile_id  utf-8, e.g. b"hybrid_standard"
  1 byte    num_components
  for each component:
    1 byte    alg_id_len
    N bytes   alg_id            utf-8, e.g. b"mlkem768"
    2 bytes   ciphertext_len
    N bytes   ciphertext

This header only carries the KEY-ESTABLISHMENT metadata (which sources
were used and their ciphertexts) - it does NOT carry the actual
symmetric-encrypted payload or its own nonce/tag; callers are expected to
append this header in front of whatever AEAD ciphertext format they
already use (e.g. Secure Vault's existing AES-256-GCM container).
"""

from __future__ import annotations

import struct
from dataclasses import dataclass

MAGIC = b"CFLX"
FORMAT_VERSION = 1


class HeaderParseError(ValueError):
    pass


@dataclass(frozen=True)
class CryptoflexHeader:
    profile_id: str
    components: list[tuple[str, bytes]]  # (algorithm_id, ciphertext)

    def to_bytes(self) -> bytes:
        out = bytearray()
        out += MAGIC
        out += struct.pack("B", FORMAT_VERSION)

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

        return bytes(out)

    @staticmethod
    def from_bytes(data: bytes) -> tuple["CryptoflexHeader", int]:
        """Parse a header from the start of `data`. Returns (header,
        bytes_consumed) so the caller can slice off the rest of the
        payload (e.g. the AEAD ciphertext) that follows."""
        if len(data) < 6 or data[:4] != MAGIC:
            raise HeaderParseError("missing or invalid cryptoflex header magic")

        offset = 4
        version = data[offset]
        offset += 1
        if version != FORMAT_VERSION:
            raise HeaderParseError(
                f"unsupported cryptoflex header version {version}; "
                f"this library supports version {FORMAT_VERSION}. "
                f"A newer/older library version may be required to read this file."
            )

        profile_id_len = data[offset]
        offset += 1
        profile_id = data[offset : offset + profile_id_len].decode("utf-8")
        offset += profile_id_len

        num_components = data[offset]
        offset += 1

        components: list[tuple[str, bytes]] = []
        for _ in range(num_components):
            alg_len = data[offset]
            offset += 1
            alg_id = data[offset : offset + alg_len].decode("utf-8")
            offset += alg_len

            (ct_len,) = struct.unpack(">H", data[offset : offset + 2])
            offset += 2
            ciphertext = data[offset : offset + ct_len]
            offset += ct_len

            components.append((alg_id, ciphertext))

        return CryptoflexHeader(profile_id=profile_id, components=components), offset
