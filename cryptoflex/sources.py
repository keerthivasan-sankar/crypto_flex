"""
cryptoflex.sources
===================

Defines the `SecuritySource` interface: a uniform wrapper around a single
key-establishment primitive (classical or post-quantum).

Design principle
-----------------
This module does NOT implement any cryptographic math itself. It wraps
existing, audited primitives:

  - ClassicalSource   -> X25519 via the `cryptography` package
  - PQCSource         -> ML-KEM via `liboqs-python` (optional dependency)

If liboqs is not installed/built on the host machine, PQCSource reports
itself as unavailable rather than crashing the whole library. This lets
callers (and the PolicyEngine) degrade gracefully to classical-only mode.

A `MockPQCSource` is also provided purely for testing the combiner logic
without requiring a compiled liboqs on the test machine. It is NOT
cryptographically secure and must never be used outside the test suite.
"""

from __future__ import annotations

import abc
import os
from dataclasses import dataclass
from typing import Any, Optional

# --- try to import the real PQC binding; degrade gracefully if absent ---
#
# Note on liboqs-python's import-time behavior: if no liboqs shared
# library is found on the system, `import oqs` will attempt to clone and
# compile liboqs FROM SOURCE on the spot (a multi-minute build, since it
# builds every KEM and signature scheme liboqs ships, not just what we
# need). That's a legitimate one-time cost for an end user's real
# machine, but it's wrong behavior for CI/test/dev environments where you
# want a fast, predictable "PQC unavailable" result instead of an
# unbounded build. Setting CRYPTOFLEX_DISABLE_PQC=1 skips the import
# entirely and makes PQCSource report itself as unavailable immediately -
# this is the supported way to run this library's test suite, or any app
# built on it, without a pre-built liboqs on hand.
#
# `oqs` is typed as `Any` rather than left for mypy to infer as `None`:
# the module is genuinely absent at runtime in disabled/unavailable cases
# (guarded by `_require_available()` before every use), but typing it as
# `None` makes mypy treat every `oqs.KeyEncapsulation(...)` call below as
# an error, which is noise rather than a real type problem the guard
# doesn't already cover.
oqs: Any = None
if os.environ.get("CRYPTOFLEX_DISABLE_PQC") == "1":
    _OQS_IMPORT_ERROR: Optional[Exception] = RuntimeError(
        "PQC disabled via CRYPTOFLEX_DISABLE_PQC=1"
    )
else:
    try:
        import oqs  # type: ignore[no-redef]
        _OQS_IMPORT_ERROR = None
    except Exception as e:  # pragma: no cover - exact exception type varies by platform
        _OQS_IMPORT_ERROR = e

from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)


@dataclass(frozen=True)
class Encapsulation:
    """Result of an encapsulation operation (KEM-style, used uniformly for
    both classical DH and real KEMs so the combiner can treat them the same
    way)."""
    ciphertext: bytes      # what the initiator sends to the responder
    shared_secret: bytes   # secret only the initiator knows at this point


class SourceUnavailableError(RuntimeError):
    """Raised when a caller tries to use a source that reported itself
    unavailable (e.g. liboqs not installed) instead of silently returning
    weak/garbage key material."""


class SecuritySource(abc.ABC):
    """Uniform interface every security source must implement.

    All sources are modeled as KEMs for uniformity, even X25519 (which is
    natively a DH primitive). This keeps the combiner logic identical
    regardless of what's underneath.
    """

    #: short stable identifier used in serialized headers - never change
    #: this once a source ships, or old ciphertexts become unreadable
    algorithm_id: str = "abstract"

    @abc.abstractmethod
    def is_available(self) -> bool:
        """Return True if this source can actually be used right now on
        this machine (e.g. required native library is present)."""

    @abc.abstractmethod
    def generate_keypair(self) -> tuple[bytes, object]:
        """Return (public_key_bytes, private_key_handle).

        private_key_handle is opaque to callers outside this module - it's
        whatever this source needs internally to later decapsulate.
        """

    @abc.abstractmethod
    def encapsulate(self, peer_public_key: bytes) -> Encapsulation:
        """Given the peer's public key, produce a ciphertext + shared secret."""

    @abc.abstractmethod
    def decapsulate(self, private_key_handle: object, ciphertext: bytes) -> bytes:
        """Recover the shared secret from a ciphertext using our private key."""

    @abc.abstractmethod
    def serialize_private(self, private_key_handle: object) -> bytes:
        """Export a private key handle to bytes so it can be stored
        (encrypted, by the caller) and reloaded in a later process. Needed
        for any use case where a keypair is a persistent identity rather
        than a one-shot ephemeral handshake."""

    @abc.abstractmethod
    def deserialize_private(self, data: bytes) -> object:
        """Reconstruct a private key handle from bytes produced by
        serialize_private()."""


class ClassicalSource(SecuritySource):
    """X25519 elliptic-curve Diffie-Hellman, modeled as a KEM.

    Security assumption: hardness of the elliptic-curve discrete log
    problem. Broken by a sufficiently large fault-tolerant quantum
    computer (Shor's algorithm) - this source alone is NOT quantum-safe.
    It remains valuable in a hybrid combiner because it is extremely
    well-audited and battle-tested; if the newer PQC math has an
    undiscovered flaw, X25519 still holds classical security.
    """

    algorithm_id = "x25519"

    def is_available(self) -> bool:
        return True  # pure Python/cryptography package, always available

    def generate_keypair(self) -> tuple[bytes, object]:
        priv = X25519PrivateKey.generate()
        pub_bytes = priv.public_key().public_bytes_raw()
        return pub_bytes, priv

    def encapsulate(self, peer_public_key: bytes) -> Encapsulation:
        # "Encapsulation" for a DH primitive: generate an ephemeral keypair,
        # do DH with the peer's static public key, and send our ephemeral
        # public key as the "ciphertext".
        eph_priv = X25519PrivateKey.generate()
        eph_pub = eph_priv.public_key().public_bytes_raw()
        peer_pub = X25519PublicKey.from_public_bytes(peer_public_key)
        shared_secret = eph_priv.exchange(peer_pub)
        return Encapsulation(ciphertext=eph_pub, shared_secret=shared_secret)

    def decapsulate(self, private_key_handle: object, ciphertext: bytes) -> bytes:
        priv: X25519PrivateKey = private_key_handle  # type: ignore
        eph_pub = X25519PublicKey.from_public_bytes(ciphertext)
        return priv.exchange(eph_pub)

    def serialize_private(self, private_key_handle: object) -> bytes:
        priv: X25519PrivateKey = private_key_handle  # type: ignore
        return priv.private_bytes_raw()

    def deserialize_private(self, data: bytes) -> object:
        return X25519PrivateKey.from_private_bytes(data)


class PQCSource(SecuritySource):
    """Post-quantum KEM, backed by liboqs.

    Security assumption: hardness of module-lattice problems (for
    ML-KEM). Standardized by NIST (FIPS 203). Believed resistant to
    both classical and quantum attack, but has a shorter track record
    of cryptanalysis than X25519 - which is exactly why this library
    combines it with a classical source rather than using it alone.
    """

    def __init__(self, kem_name: str = "ML-KEM-768"):
        self.kem_name = kem_name
        self.algorithm_id = kem_name.lower().replace("-", "")

    def is_available(self) -> bool:
        if oqs is None:
            return False
        try:
            return self.kem_name in oqs.get_enabled_kem_mechanisms()
        except Exception:
            return False

    def _require_available(self):
        if not self.is_available():
            hint = f" (import error: {_OQS_IMPORT_ERROR})" if _OQS_IMPORT_ERROR else ""
            raise SourceUnavailableError(
                f"PQC source '{self.kem_name}' is not available on this "
                f"machine - liboqs may not be installed/built{hint}. "
                f"See README for installation instructions."
            )

    def generate_keypair(self) -> tuple[bytes, object]:
        self._require_available()
        kem = oqs.KeyEncapsulation(self.kem_name)
        pub = kem.generate_keypair()
        # keep the KEM object alive - it holds the secret key internally
        return pub, kem

    def encapsulate(self, peer_public_key: bytes) -> Encapsulation:
        self._require_available()
        with oqs.KeyEncapsulation(self.kem_name) as kem:
            ciphertext, shared_secret = kem.encap_secret(peer_public_key)
            return Encapsulation(ciphertext=ciphertext, shared_secret=shared_secret)

    def decapsulate(self, private_key_handle: object, ciphertext: bytes) -> bytes:
        self._require_available()
        kem: Any = private_key_handle  # the live oqs.KeyEncapsulation from generate_keypair
        return kem.decap_secret(ciphertext)

    def serialize_private(self, private_key_handle: object) -> bytes:
        self._require_available()
        kem: Any = private_key_handle
        return kem.export_secret_key()

    def deserialize_private(self, data: bytes) -> object:
        self._require_available()
        return oqs.KeyEncapsulation(self.kem_name, secret_key=data)


class MockPQCSource(SecuritySource):
    """FOR TESTS ONLY. Simulates a PQC-shaped source using plain randomness
    so the combiner/policy logic can be exercised on machines without a
    compiled liboqs. This provides NO real security and must never be
    selected by the PolicyEngine outside of test mode.
    """

    algorithm_id = "mock-pqc-test-only"

    def is_available(self) -> bool:
        return True

    def generate_keypair(self) -> tuple[bytes, object]:
        priv = os.urandom(32)
        pub = priv  # trivial "public key" - purely for shape/testing
        return pub, priv

    def encapsulate(self, peer_public_key: bytes) -> Encapsulation:
        secret = os.urandom(32)
        # "ciphertext" just carries the secret XORed with the peer key so
        # decapsulate can recover it deterministically - NOT SECURE, TEST ONLY
        ciphertext = bytes(a ^ b for a, b in zip(secret, peer_public_key))
        return Encapsulation(ciphertext=ciphertext, shared_secret=secret)

    def decapsulate(self, private_key_handle: object, ciphertext: bytes) -> bytes:
        priv: bytes = private_key_handle  # type: ignore
        return bytes(a ^ b for a, b in zip(ciphertext, priv))

    def serialize_private(self, private_key_handle: object) -> bytes:
        return private_key_handle  # type: ignore

    def deserialize_private(self, data: bytes) -> object:
        return data
