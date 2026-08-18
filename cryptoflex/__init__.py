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
    derive_root_key,
    establish_keys,
    recover_root_key,
)
from .header import CryptoflexHeader, HeaderParseError
from .policy import Constraint, PolicyDecision, PolicyEngine
from .profiles import PROFILES, SecurityProfile, get_profile
from .sources import (
    ClassicalSource,
    Encapsulation,
    PQCSource,
    SecuritySource,
    SourceUnavailableError,
)

__version__ = "0.1.0"

__all__ = [
    "establish_keys",
    "derive_root_key",
    "recover_root_key",
    "KeySet",
    "PublicBundle",
    "DerivedRoot",
    "CryptoflexHeader",
    "HeaderParseError",
    "PolicyEngine",
    "PolicyDecision",
    "Constraint",
    "PROFILES",
    "SecurityProfile",
    "get_profile",
    "SecuritySource",
    "ClassicalSource",
    "PQCSource",
    "Encapsulation",
    "SourceUnavailableError",
]
