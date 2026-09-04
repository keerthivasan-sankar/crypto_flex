"""
cryptoflex - a local-first crypto-agility policy engine.

Orchestrates existing, audited cryptographic primitives (classical X25519,
post-quantum ML-KEM via liboqs) behind a policy engine that picks the
right combination based on local signals only - no network calls, no
external services.

See README.md for the full design rationale.
"""

from .api import (
    DerivedRoot,
    KeySet,
    PublicBundle,
    decrypt,
    derive_root_key,
    encrypt,
    establish_keys,
    migrate,
    migrate_file,
    recover_root_key,
)
from .ephemeral import WireMessage, ephemeral_decrypt, ephemeral_encrypt
from .errors import DecryptionError, DowngradeError
from .header import CryptoflexHeader, HeaderParseError
from .keystore import (
    deserialize_public_bundle,
    export_keyset_bytes,
    import_keyset_bytes,
    serialize_public_bundle,
)
from .policy import Constraint, PolicyDecision, PolicyEngine
from .profiles import PROFILES, SecurityProfile, get_profile
from .sources import (
    ClassicalSource,
    Encapsulation,
    PQCSource,
    SecuritySource,
    SourceUnavailableError,
)
from .streaming import decrypt_stream, encrypt_stream, migrate_stream
from .utils import zeroize

__version__ = "0.4.1"

__all__ = [
    # high-level AEAD API (recommended for file encryption)
    "encrypt",
    "decrypt",
    # migration API (crypto-agility re-encryption)
    "migrate",
    "migrate_file",
    "migrate_stream",
    # ephemeral / forward-secret messaging API
    "ephemeral_encrypt",
    "ephemeral_decrypt",
    "WireMessage",
    # streaming AEAD API (large files)
    "encrypt_stream",
    "decrypt_stream",
    # password-encrypted keystore
    "export_keyset_bytes",
    "import_keyset_bytes",
    "serialize_public_bundle",
    "deserialize_public_bundle",
    # memory security
    "zeroize",
    # low-level key derivation
    "establish_keys",
    "derive_root_key",
    "recover_root_key",
    # data classes
    "KeySet",
    "PublicBundle",
    "DerivedRoot",
    # header
    "CryptoflexHeader",
    "HeaderParseError",
    # policy
    "PolicyEngine",
    "PolicyDecision",
    "Constraint",
    # profiles
    "PROFILES",
    "SecurityProfile",
    "get_profile",
    # sources
    "SecuritySource",
    "ClassicalSource",
    "PQCSource",
    "Encapsulation",
    "SourceUnavailableError",
    # errors
    "DecryptionError",
    "DowngradeError",
]

