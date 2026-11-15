"""
Shared test fixtures used across multiple test modules.

Centralizes the _FixedProfileEngine helper and introduces a robust
profile registry isolation fixture.
"""

from __future__ import annotations

from contextlib import contextmanager
from types import MappingProxyType
import pytest

import cryptoflex as crypto_mod
from cryptoflex import profiles as profiles_module
import cryptoflex.policy as policy_mod
from cryptoflex.policy import Constraint, PolicyDecision
from cryptoflex.profiles import SecurityProfile
from cryptoflex.sources import ClassicalSource, MockPQCSource

# ------------------------------------------------------------
# Capture original production references at module import time
# before any test fixtures execute.
# ------------------------------------------------------------
ORIGINAL_CRYPTO_PROFILES = crypto_mod.PROFILES
ORIGINAL_PROFILES_PROFILES = profiles_module.PROFILES
ORIGINAL_POLICY_PROFILES = policy_mod.PROFILES

assert ORIGINAL_PROFILES_PROFILES is ORIGINAL_POLICY_PROFILES
assert ORIGINAL_PROFILES_PROFILES is ORIGINAL_CRYPTO_PROFILES
assert type(ORIGINAL_PROFILES_PROFILES) is dict


class FixedProfileEngine:
    """Test-only stand-in for PolicyEngine that always returns a specific
    profile, so we can exercise the hybrid path using MockPQCSource
    without depending on liboqs being built in the test environment.
    """

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


@pytest.fixture(name="FixedProfileEngine")
def _fixed_profile_engine_fixture():
    return FixedProfileEngine


@pytest.fixture(scope="session")
def original_production_profiles():
    """Session-scoped fixture providing the captured original production PROFILES dict."""
    return ORIGINAL_PROFILES_PROFILES


@contextmanager
def isolated_registry_context():
    """Context manager for temporary profile registry isolation.
    Builds an independent registry, replaces all three module aliases with
    the read-only mapping proxy, yields (proxy, inject_fn), and restores
    all three aliases upon context exit.
    """
    orig_profiles = profiles_module.PROFILES
    orig_policy = policy_mod.PROFILES
    orig_crypto = crypto_mod.PROFILES

    test_registry = profiles_module._profile_registry()
    proxy = MappingProxyType(test_registry)

    def inject(custom_profile: SecurityProfile):
        if custom_profile.profile_id in test_registry:
            raise ValueError(f"Duplicate profile_id {custom_profile.profile_id}")
        test_registry[custom_profile.profile_id] = custom_profile

    profiles_module.PROFILES = proxy
    policy_mod.PROFILES = proxy
    crypto_mod.PROFILES = proxy
    try:
        yield proxy, inject
    finally:
        profiles_module.PROFILES = orig_profiles
        policy_mod.PROFILES = orig_policy
        crypto_mod.PROFILES = orig_crypto


@pytest.fixture
def registry_context():
    """Expose the single isolated_registry_context implementation to tests."""
    return isolated_registry_context


@pytest.fixture
def registry_restoration_probe():
    """Teardown probe fixture.
    Runs setup BEFORE isolated_profile_registry patches the aliases.
    During teardown (which executes AFTER monkeypatch has restored the aliases),
    verifies that all three module aliases are restored to their original production identities.
    """
    probe_record = {"setup": True, "torn_down": False}
    yield probe_record
    assert profiles_module.PROFILES is ORIGINAL_PROFILES_PROFILES, (
        "profiles.PROFILES was not restored to original production identity"
    )
    assert policy_mod.PROFILES is ORIGINAL_POLICY_PROFILES, (
        "policy.PROFILES was not restored to original production identity"
    )
    assert crypto_mod.PROFILES is ORIGINAL_CRYPTO_PROFILES, (
        "crypto.PROFILES was not restored to original production identity"
    )
    probe_record["torn_down"] = True


@pytest.fixture(scope="function", autouse=True)
def isolated_profile_registry(registry_restoration_probe, monkeypatch):
    """Replace the global PROFILES mapping with an isolated, read-only proxy.
    Depends on registry_restoration_probe so that probe teardown verifies
    restoration after monkeypatch has restored the aliases.
    """
    test_registry = profiles_module._profile_registry()
    proxy = MappingProxyType(test_registry)

    monkeypatch.setattr(profiles_module, "PROFILES", proxy, raising=True)
    monkeypatch.setattr(policy_mod, "PROFILES", proxy, raising=True)
    monkeypatch.setattr(crypto_mod, "PROFILES", proxy, raising=True)

    def inject(custom_profile: SecurityProfile):
        """Inject a custom profile into the isolated registry.
        Raises ``ValueError`` on duplicate ``profile_id``.
        """
        if custom_profile.profile_id in test_registry:
            raise ValueError(f"Duplicate profile_id {custom_profile.profile_id}")
        test_registry[custom_profile.profile_id] = custom_profile

    yield inject


@pytest.fixture
def inject(isolated_profile_registry):
    """Alias fixture providing the ``inject`` callable for backward compatibility.
    Tests that request ``inject`` (e.g., ``hybrid_mock_profile``) receive the
    helper returned by the ``isolated_profile_registry`` autouse fixture.
    """
    return isolated_profile_registry


@pytest.fixture
def hybrid_mock_profile(inject):
    """Register a mock hybrid profile (X25519 + MockPQCSource) into the isolated
    registry for the duration of a test."""
    profile = SecurityProfile(
        profile_id="hybrid_mock_test",
        display_name="Hybrid (test mock)",
        sources=[ClassicalSource(), MockPQCSource()],
        risk_tier="current",
        strength_level=1,
    )
    inject(profile)
    return profile


@pytest.fixture
def classical_only_mock_profile(inject):
    """A classical-only profile using a real ``ClassicalSource`` for tests that
    need to control profile selection.
    """
    profile = SecurityProfile(
        profile_id="classical_test",
        display_name="Classical (test)",
        sources=[ClassicalSource()],
        risk_tier="legacy",
        strength_level=0,
    )
    inject(profile)
    return profile
