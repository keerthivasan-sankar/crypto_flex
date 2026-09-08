"""
cryptoflex.policy
====================

The PolicyEngine is the actual novel piece of this project.  Everything
else (sources, combiner, profiles) is orchestration around existing,
trusted cryptography.  This module is the "brain" that decides WHICH
profile an application should use, based entirely on LOCAL signals:

  - What's actually available on this machine (is liboqs built?)
  - The caller's stated constraint (prioritize speed vs. max security)
  - A locally bundled, versioned risk table (algorithm_status.json,
    shipped with the package - NOT fetched over the network)

Explicitly out of scope (by design, to stay local-first / no external
dependency):
  - Live network calls to check NIST/CNSA advisories
  - Any telemetry, phone-home, or remote policy fetch

If you need live threat-feed awareness, update the bundled JSON table
and release a new package version - that keeps a hard boundary against
this becoming a network-dependent trust-a-third-party system.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from enum import Enum
from importlib import resources
from typing import Optional

from .profiles import PROFILES, SecurityProfile


class Constraint(str, Enum):
    FAST = "fast"                # minimize compute/latency
    BALANCED = "balanced"        # default
    MAX_SECURITY = "max_security"  # prefer highest assurance available


@dataclass(frozen=True)
class PolicyDecision:
    profile: SecurityProfile
    reason: str
    #: True if the ideal profile for the constraint wasn't available and
    #: we fell back to something weaker - callers should surface this,
    #: e.g. log it or warn the user, rather than silently downgrading
    degraded: bool
    #: Recommended minimum profile ID that the decryptor should enforce.
    #: Defaults to the selected profile's ID.  Applications can persist
    #: this alongside ciphertext so the decryptor refuses downgrades.
    min_accepted_profile: str = ""

    def __post_init__(self):
        if not self.min_accepted_profile:
            # frozen=True requires __setattr__ bypass
            object.__setattr__(self, "min_accepted_profile", self.profile.profile_id)


def _load_risk_table() -> dict:
    with resources.files("cryptoflex").joinpath("algorithm_status.json").open(
        "r", encoding="utf-8"
    ) as f:
        return json.load(f)


class PolicyEngine:
    def __init__(self, risk_table: Optional[dict] = None):
        self.risk_table = risk_table if risk_table is not None else _load_risk_table()

    def _is_profile_acceptable(self, profile: SecurityProfile, require_quantum_safe: bool) -> tuple[bool, bool, str]:
        """Validates that a profile is acceptable under current policy.
        
        Enforces a fail-closed model: any missing, unknown, or malformed
        metadata in the risk table causes the profile to be rejected.

        Returns (is_acceptable, is_degraded, reason_if_degraded). A profile with at least
        one 'approved' component is usable but is considered 'degraded' if any component
        is 'deprecated'.
        """
        algos = self.risk_table.get("algorithms")
        if not isinstance(algos, dict):
            return False, False, ""

        statuses = []
        is_qs = False
        deprecated_components = []
        for source in profile.sources:
            record = algos.get(source.algorithm_id)
            if not isinstance(record, dict):
                return False, False, ""  # Missing or malformed record -> fail closed

            status = record.get("status")
            if status not in ("approved", "deprecated"):
                return False, False, ""  # Unknown, missing, or disallowed status -> fail closed
            statuses.append(status)
            if status == "deprecated":
                deprecated_components.append(source.algorithm_id)

            qs_flag = record.get("quantum_safe")
            if qs_flag is True:
                is_qs = True
            elif qs_flag is not False:
                return False, False, ""  # Malformed quantum_safe flag -> fail closed

        if require_quantum_safe and not is_qs:
            return False, False, ""

        # A profile is fully deprecated only if EVERY source is deprecated.
        # This matches the hybrid combiner security property.
        if all(s == "deprecated" for s in statuses):
            return False, False, ""

        is_degraded = len(deprecated_components) > 0
        reason = ""
        if is_degraded:
            reason = f"contains deprecated component(s): {', '.join(deprecated_components)}"

        return True, is_degraded, reason

    def _candidate_order(self, constraint: Constraint) -> list[str]:
        """Ordered list of profile_ids to try, best-first, for a given
        constraint.  This ordering is the actual "policy" - it's the part
        a maintainer or downstream app can override/extend."""
        if constraint == Constraint.FAST:
            return ["classical_only", "hybrid_standard", "hybrid_high"]
        if constraint == Constraint.MAX_SECURITY:
            return ["hybrid_high", "hybrid_standard", "classical_only"]
        # BALANCED default: prefer PQC-hybrid, but not the heaviest one
        return ["hybrid_standard", "hybrid_high", "classical_only"]

    def decide(
        self,
        constraint: Constraint = Constraint.BALANCED,
        *,
        require_quantum_safe: bool = False,
    ) -> PolicyDecision:
        """Pick a SecurityProfile given the caller's constraint.

        require_quantum_safe=True refuses to fall back to classical_only
        even if nothing else is available, raising instead - use this when
        the caller would rather fail loudly than silently ship non-PQC
        protection.
        """
        candidates = self._candidate_order(constraint)
        ideal_id = candidates[0]

        for i, profile_id in enumerate(candidates):
            profile = PROFILES[profile_id]

            if not profile.is_available():
                continue

            acceptable, mixed_degraded, mixed_reason = self._is_profile_acceptable(profile, require_quantum_safe)
            if not acceptable:
                continue

            degraded = profile_id != ideal_id or mixed_degraded
            
            reason_parts = [f"selected '{profile_id}' for constraint={constraint.value}"]
            if profile_id != ideal_id:
                reason_parts.append(f"(fell back from '{ideal_id}': unavailable or deprecated)")
            if mixed_degraded:
                reason_parts.append(f"(degraded: {mixed_reason})")
                
            reason = " ".join(reason_parts)
            return PolicyDecision(
                profile=profile,
                reason=reason,
                degraded=degraded,
                min_accepted_profile=profile_id,
            )

        raise RuntimeError(
            "No acceptable security profile available: all candidates were "
            "either unavailable on this machine or deprecated by the risk "
            f"table (require_quantum_safe={require_quantum_safe}). "
            "This is a hard stop, not a silent fallback to weak crypto."
        )
