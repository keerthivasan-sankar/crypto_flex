"""
cryptoflex.profiles
======================

Named, fixed combinations of SecuritySources.  A profile defines WHICH
sources to use and in WHAT ORDER (order matters - see combiner.py).

Profiles are intentionally static and named, not built ad-hoc, so that a
serialized header can just store a short profile ID and both sides of a
handshake/file know exactly which sources + order to reconstruct.

Design change (Discussion #2534 feedback):
  "Make downgrade semantics explicit.  A runtime policy may choose
  classical-only for availability, but a decryptor should not silently
  accept a weaker profile where the file or caller requires hybrid
  protection."

Each profile now carries a ``strength_level`` integer that defines a
total ordering of profile security strength.  The decrypt() API uses
this to enforce a minimum accepted profile.
"""

from __future__ import annotations

from dataclasses import dataclass

from .sources import ClassicalSource, PQCSource, SecuritySource


@dataclass(frozen=True)
class SecurityProfile:
    profile_id: str
    display_name: str
    sources: list[SecuritySource]
    #: informal risk tier, used by the PolicyEngine's bundled risk table
    #: to decide if this profile is still recommended
    risk_tier: str  # "current" | "legacy" | "deprecated"
    #: integer strength level for downgrade enforcement.
    #: Higher = stronger.  The decrypt() API rejects headers whose
    #: profile strength_level is below the caller's min_profile.
    strength_level: int = 0

    def is_available(self) -> bool:
        return all(s.is_available() for s in self.sources)


def _profile_registry() -> dict[str, SecurityProfile]:
    x25519 = ClassicalSource()
    mlkem768 = PQCSource("ML-KEM-768")
    mlkem1024 = PQCSource("ML-KEM-1024")

    profiles = [
        SecurityProfile(
            profile_id="classical_only",
            display_name="Classical (X25519)",
            sources=[x25519],
            risk_tier="legacy",  # not quantum-safe; kept for compat/perf
            strength_level=0,
        ),
        SecurityProfile(
            profile_id="hybrid_standard",
            display_name="Hybrid Standard (X25519 + ML-KEM-768)",
            sources=[x25519, mlkem768],
            risk_tier="current",
            strength_level=1,
        ),
        SecurityProfile(
            profile_id="hybrid_high",
            display_name="Hybrid High Assurance (X25519 + ML-KEM-1024)",
            sources=[x25519, mlkem1024],
            risk_tier="current",
            strength_level=2,
        ),
    ]
    return {p.profile_id: p for p in profiles}


PROFILES: dict[str, SecurityProfile] = _profile_registry()


def get_profile(profile_id: str) -> SecurityProfile:
    try:
        return PROFILES[profile_id]
    except KeyError:
        raise ValueError(
            f"Unknown profile_id '{profile_id}'. Known profiles: "
            f"{list(PROFILES.keys())}"
        )
