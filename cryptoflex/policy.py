"""
cryptoflex.policy
====================

The PolicyEngine is the actual novel piece of this project. Everything
else (sources, combiner, profiles) is orchestration around existing,
trusted cryptography. This module is the "brain" that decides WHICH
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


def _load_risk_table() -> dict:
    with resources.files("cryptoflex").joinpath("algorithm_status.json").open(
        "r", encoding="utf-8"
    ) as f:
        return json.load(f)


class PolicyEngine:
    def __init__(self, risk_table: Optional[dict] = None):
        self.risk_table = risk_table if risk_table is not None else _load_risk_table()

    def _profile_deprecated(self, profile: SecurityProfile) -> bool:
        """A profile is only fully deprecated if EVERY source in it is
        deprecated - not if just one is. This matches the actual security
        property of a hybrid combiner: the combined key is safe as long
        as at least one component remains sound, so a hybrid profile
        with one deprecated component and one healthy component is still
        usable (and still strictly better than a single-source profile
        using only the deprecated algorithm)."""
        algos = self.risk_table.get("algorithms", {})
        statuses = [
            algos.get(source.algorithm_id, {}).get("status") for source in profile.sources
        ]
        return len(statuses) > 0 and all(status == "deprecated" for status in statuses)

    def _candidate_order(self, constraint: Constraint) -> list[str]:
        """Ordered list of profile_ids to try, best-first, for a given
        constraint. This ordering is the actual "policy" - it's the part
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

            if self._profile_deprecated(profile):
                continue

            if not profile.is_available():
                continue

            if require_quantum_safe:
                algos = self.risk_table.get("algorithms", {})
                quantum_safe = any(
                    algos.get(s.algorithm_id, {}).get("quantum_safe")
                    for s in profile.sources
                )
                if not quantum_safe:
                    continue

            degraded = profile_id != ideal_id
            reason = (
                f"selected '{profile_id}' for constraint={constraint.value}"
                + (
                    f" (fell back from '{ideal_id}': unavailable or deprecated)"
                    if degraded
                    else ""
                )
            )
            return PolicyDecision(profile=profile, reason=reason, degraded=degraded)

        raise RuntimeError(
            "No acceptable security profile available: all candidates were "
            "either unavailable on this machine or deprecated by the risk "
            f"table (require_quantum_safe={require_quantum_safe}). "
            "This is a hard stop, not a silent fallback to weak crypto."
        )
