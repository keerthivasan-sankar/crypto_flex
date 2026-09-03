"""
Shared test fixtures used across multiple test modules.

Centralizes the _FixedProfileEngine helper and the hybrid_mock_profile
fixture that were previously duplicated in test_integration.py and
test_adversarial.py.
"""

from __future__ import annotations

import pytest

from cryptoflex import profiles as profiles_module
from cryptoflex.policy import Constraint, PolicyDecision
from cryptoflex.profiles import SecurityProfile
from cryptoflex.sources import ClassicalSource, MockPQCSource


class FixedProfileEngine:
    """Test-only stand-in for PolicyEngine that always returns a specific
    profile, so we can exercise the hybrid path using MockPQCSource
    without depending on liboqs being built in the test environment."""

    def __init__(self, profile: SecurityProfile):
        self._profile = profile

    def decide(self, constraint=Constraint.BALANCED, *, require_quantum_safe=False):
        return PolicyDecision(
            profile=self._profile,
            reason="forced for test",
            degraded=False,
            min_accepted_profile=self._profile.profile_id,
        )


@pytest.fixture
def FixedProfileEngine_fixture():
    return FixedProfileEngine


# Expose class as a fixture name matching `FixedProfileEngine`
@pytest.fixture(name="FixedProfileEngine")
def _fixed_profile_engine_fixture():
    return FixedProfileEngine


@pytest.fixture
def hybrid_mock_profile():
    """Register a mock hybrid profile (X25519 + MockPQCSource) into the
    live profile registry for the duration of a test, then clean up."""
    profile = SecurityProfile(
        profile_id="hybrid_mock_test",
        display_name="Hybrid (test mock)",
        sources=[ClassicalSource(), MockPQCSource()],
        risk_tier="current",
        strength_level=1,
    )
    profiles_module.PROFILES[profile.profile_id] = profile
    yield profile
    del profiles_module.PROFILES[profile.profile_id]


@pytest.fixture
def classical_only_mock_profile():
    """A classical-only profile using real ClassicalSource, registered
    temporarily for tests that need to control profile selection."""
    profile = SecurityProfile(
        profile_id="classical_test",
        display_name="Classical (test)",
        sources=[ClassicalSource()],
        risk_tier="legacy",
        strength_level=0,
    )
    profiles_module.PROFILES[profile.profile_id] = profile
    yield profile
    del profiles_module.PROFILES[profile.profile_id]
