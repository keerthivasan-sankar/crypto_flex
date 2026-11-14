"""
Regression tests for the profile registry isolation fixture and context manager.
"""

from __future__ import annotations

from types import MappingProxyType
import pytest

import cryptoflex as crypto_mod
import cryptoflex.policy as policy_mod
from cryptoflex import profiles as profiles_mod
from cryptoflex.profiles import SecurityProfile
from cryptoflex.sources import ClassicalSource, MockPQCSource

# Capture original production references at import time
ORIGINAL_CRYPTO_PROFILES = crypto_mod.PROFILES
ORIGINAL_POLICY_PROFILES = policy_mod.PROFILES
ORIGINAL_PROFILES_PROFILES = profiles_mod.PROFILES


# ------------------------------------------------------------
# Helper fixtures
# ------------------------------------------------------------

@pytest.fixture
def inject_helper(isolated_profile_registry):
    """Expose the ``inject`` helper from the autouse fixture.
    The autouse fixture yields the ``inject`` callable, so we can use it
    directly in tests.
    """
    return isolated_profile_registry


@pytest.fixture
def temp_profile(isolated_profile_registry):
    """Inject a temporary profile for the duration of a test.
    The fixture returns the injected profile object.
    """
    profile = SecurityProfile(
        profile_id="temp_profile",
        display_name="Temp Profile",
        sources=[ClassicalSource()],
        risk_tier="legacy",
        strength_level=0,
    )
    isolated_profile_registry(profile)
    return profile


# ------------------------------------------------------------
# Tests
# ------------------------------------------------------------

def test_shallow_copy_shares_objects():
    """Verify that a shallow copy of the production registry shares profile
    and source references, demonstrating why a shallow copy is insufficient for isolation.
    Does not mutate any production objects.
    """
    shallow = dict(ORIGINAL_PROFILES_PROFILES)
    assert shallow is not ORIGINAL_PROFILES_PROFILES
    for profile_id, orig_profile in ORIGINAL_PROFILES_PROFILES.items():
        assert shallow[profile_id] is orig_profile
        assert shallow[profile_id].sources is orig_profile.sources
        for shallow_src, orig_src in zip(shallow[profile_id].sources, orig_profile.sources):
            assert shallow_src is orig_src


def test_source_object_independence():
    """Verify that no profile or source object in the isolated test registry
    is shared with the production registry.
    """
    assert profiles_mod.PROFILES is not ORIGINAL_PROFILES_PROFILES
    for profile_id, test_prof in profiles_mod.PROFILES.items():
        orig_prof = ORIGINAL_PROFILES_PROFILES[profile_id]
        assert test_prof is not orig_prof
        assert test_prof.sources is not orig_prof.sources
        for test_src, orig_src in zip(test_prof.sources, orig_prof.sources):
            assert test_src is not orig_src


def test_shared_reference_topology():
    """Verify that the test registry preserves the production sharing topology:
    - All three profiles share the exact same X25519 source instance.
    - The hybrid profiles have distinct PQC source instances.
    """
    x_classical = profiles_mod.PROFILES["classical_only"].sources[0]
    x_standard = profiles_mod.PROFILES["hybrid_standard"].sources[0]
    x_high = profiles_mod.PROFILES["hybrid_high"].sources[0]

    assert x_classical is x_standard
    assert x_standard is x_high

    pqc_standard = profiles_mod.PROFILES["hybrid_standard"].sources[1]
    pqc_high = profiles_mod.PROFILES["hybrid_high"].sources[1]
    assert pqc_standard is not pqc_high


def test_isolation_prevents_source_mutation(inject_helper):
    """Verify that mutating source attributes in the isolated registry
    cannot affect the captured production registry.
    Uses try/finally cleanup to guarantee no residual mutation.
    """
    test_x25519 = profiles_mod.PROFILES["classical_only"].sources[0]
    orig_x25519 = ORIGINAL_PROFILES_PROFILES["classical_only"].sources[0]

    assert test_x25519 is not orig_x25519

    sentinel = "sentinel_isolation_check_12345"
    orig_algo_id = getattr(test_x25519, "algorithm_id", "x25519")
    try:
        test_x25519.algorithm_id = sentinel
        assert getattr(orig_x25519, "algorithm_id", None) != sentinel
        assert getattr(orig_x25519, "algorithm_id", None) == "x25519"
    finally:
        test_x25519.algorithm_id = orig_algo_id

    custom = SecurityProfile(
        profile_id="custom_isolated_test",
        display_name="Custom Isolated Test",
        sources=[ClassicalSource(), MockPQCSource()],
        risk_tier="current",
        strength_level=1,
    )
    inject_helper(custom)
    assert "custom_isolated_test" in profiles_mod.PROFILES
    assert "custom_isolated_test" not in ORIGINAL_PROFILES_PROFILES


def test_mapping_proxy_is_immutable():
    """Direct assignment to the read-only proxy should raise ``TypeError``."""
    with pytest.raises(TypeError):
        profiles_mod.PROFILES["new"] = SecurityProfile(
            profile_id="new",
            display_name="New",
            sources=[ClassicalSource()],
            risk_tier="legacy",
            strength_level=0,
        )


def test_duplicate_injection_raises(inject_helper):
    """Injecting a profile with an existing ``profile_id`` must raise ValueError
    before any mutation occurs, leaving the original entry intact.
    """
    orig_display = profiles_mod.PROFILES["classical_only"].display_name
    dup = SecurityProfile(
        profile_id="classical_only",
        display_name="Dup",
        sources=[ClassicalSource()],
        risk_tier="legacy",
        strength_level=0,
    )
    with pytest.raises(ValueError, match="Duplicate profile_id"):
        inject_helper(dup)
    assert profiles_mod.PROFILES["classical_only"].display_name == orig_display


def test_temp_profile_is_visible(temp_profile):
    """While the ``temp_profile`` fixture is active, the profile should be present."""
    assert "temp_profile" in profiles_mod.PROFILES
    assert profiles_mod.PROFILES["temp_profile"] is temp_profile


def test_aliases_point_to_isolated_proxy():
    """While the fixture is active, all three PROFILES aliases must refer
    to the exact same MappingProxy instance, which is distinct from production.
    """
    proxy = profiles_mod.PROFILES
    assert isinstance(proxy, MappingProxyType)
    assert crypto_mod.PROFILES is proxy
    assert policy_mod.PROFILES is proxy
    assert proxy is not ORIGINAL_PROFILES_PROFILES


def test_context_manager_restoration(registry_context):
    """Verify that isolated_registry_context correctly replaces all three aliases
    and restores the exact pre-context identities upon exit.
    """
    pre_profiles = profiles_mod.PROFILES
    pre_policy = policy_mod.PROFILES
    pre_crypto = crypto_mod.PROFILES

    with registry_context() as (proxy, inject):
        assert isinstance(proxy, MappingProxyType)
        assert profiles_mod.PROFILES is proxy
        assert policy_mod.PROFILES is proxy
        assert crypto_mod.PROFILES is proxy
        assert proxy is not pre_profiles

    # After exiting, exact pre-context identities are restored
    assert profiles_mod.PROFILES is pre_profiles
    assert policy_mod.PROFILES is pre_policy
    assert crypto_mod.PROFILES is pre_crypto


def test_temporary_profile_lifecycle_in_context(registry_context):
    """Verify that a profile injected in isolated_registry_context is visible
    during the context and absent from both modules and production after exit.
    """
    temp_prof = SecurityProfile(
        profile_id="temp_ctx_lifecycle",
        display_name="Temp Context Lifecycle",
        sources=[ClassicalSource()],
        risk_tier="legacy",
        strength_level=0,
    )
    with registry_context() as (proxy, inject):
        inject(temp_prof)
        assert "temp_ctx_lifecycle" in profiles_mod.PROFILES
        assert profiles_mod.PROFILES["temp_ctx_lifecycle"] is temp_prof

    assert "temp_ctx_lifecycle" not in profiles_mod.PROFILES
    assert "temp_ctx_lifecycle" not in ORIGINAL_PROFILES_PROFILES


def test_autouse_fixture_teardown_probe(registry_restoration_probe):
    """Verify that the teardown probe fixture is wired and active.
    Its teardown hook asserts that all three module aliases are restored
    to their original production references after monkeypatch teardown.
    """
    assert registry_restoration_probe["setup"] is True


def test_module_capture_matches_conftest(original_production_profiles):
    """The module-level capture must be the same object conftest captured."""
    assert ORIGINAL_PROFILES_PROFILES is original_production_profiles
