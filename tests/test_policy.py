import pytest

from cryptoflex.policy import Constraint, PolicyEngine
from cryptoflex.profiles import PROFILES


def test_fast_constraint_prefers_classical_only():
    engine = PolicyEngine()
    decision = engine.decide(Constraint.FAST)
    assert decision.profile.profile_id == "classical_only"
    assert decision.degraded is False
    assert decision.min_accepted_profile == "classical_only"


def test_engine_always_returns_available_profile():
    engine = PolicyEngine()
    for constraint in Constraint:
        decision = engine.decide(constraint)
        assert decision.profile.is_available()


def test_balanced_and_max_security_degrade_gracefully_without_pqc():
    engine = PolicyEngine()
    hybrid_standard_available = PROFILES["hybrid_standard"].is_available()

    decision = engine.decide(Constraint.BALANCED)
    if hybrid_standard_available:
        assert decision.profile.profile_id == "hybrid_standard"
        assert decision.degraded is False
    else:
        assert decision.profile.profile_id == "classical_only"
        assert decision.degraded is True
        assert "fell back" in decision.reason


def test_require_quantum_safe_raises_when_no_pqc_available():
    hybrid_standard_available = PROFILES["hybrid_standard"].is_available()
    hybrid_high_available = PROFILES["hybrid_high"].is_available()
    engine = PolicyEngine()

    if hybrid_standard_available or hybrid_high_available:
        decision = engine.decide(Constraint.BALANCED, require_quantum_safe=True)
        assert decision.profile.profile_id in ("hybrid_standard", "hybrid_high")
    else:
        with pytest.raises(RuntimeError):
            engine.decide(Constraint.BALANCED, require_quantum_safe=True)


def test_deprecated_profile_is_skipped():
    risk_table = {
        "algorithms": {
            "x25519": {"status": "deprecated", "quantum_safe": False},
            "mlkem768": {"status": "approved", "quantum_safe": True},
            "mlkem1024": {"status": "approved", "quantum_safe": True},
        }
    }
    engine = PolicyEngine(risk_table=risk_table)

    if PROFILES["hybrid_standard"].is_available() or PROFILES["hybrid_high"].is_available():
        decision = engine.decide(Constraint.FAST)
        assert decision.profile.profile_id != "classical_only"
    else:
        with pytest.raises(RuntimeError):
            engine.decide(Constraint.FAST)


def test_all_profiles_deprecated_raises_hard_stop():
    risk_table = {
        "algorithms": {
            "x25519": {"status": "deprecated", "quantum_safe": False},
            "mlkem768": {"status": "deprecated", "quantum_safe": True},
            "mlkem1024": {"status": "deprecated", "quantum_safe": True},
        }
    }
    engine = PolicyEngine(risk_table=risk_table)
    with pytest.raises(RuntimeError):
        engine.decide(Constraint.BALANCED)


def test_policy_rejects_disallowed_status():
    risk_table = {"algorithms": {"x25519": {"status": "disallowed", "quantum_safe": False}}}
    engine = PolicyEngine(risk_table=risk_table)
    acceptable, _, _ = engine._is_profile_acceptable(PROFILES["classical_only"], False)
    assert not acceptable


def test_policy_rejects_unknown_status():
    risk_table = {"algorithms": {"x25519": {"status": "what_is_this", "quantum_safe": False}}}
    engine = PolicyEngine(risk_table=risk_table)
    acceptable, _, _ = engine._is_profile_acceptable(PROFILES["classical_only"], False)
    assert not acceptable


def test_policy_rejects_missing_status():
    risk_table = {"algorithms": {"x25519": {"quantum_safe": False}}}
    engine = PolicyEngine(risk_table=risk_table)
    acceptable, _, _ = engine._is_profile_acceptable(PROFILES["classical_only"], False)
    assert not acceptable


def test_policy_mixed_approved_deprecated_is_degraded():
    risk_table = {
        "algorithms": {
            "x25519": {"status": "deprecated", "quantum_safe": False},
            "mlkem768": {"status": "approved", "quantum_safe": True},
        }
    }
    engine = PolicyEngine(risk_table=risk_table)
    acceptable, degraded, reason = engine._is_profile_acceptable(PROFILES["hybrid_standard"], False)
    assert acceptable is True
    assert degraded is True
    assert "deprecated component(s): x25519" in reason


def test_policy_all_deprecated_is_rejected_in_check():
    risk_table = {
        "algorithms": {
            "x25519": {"status": "deprecated", "quantum_safe": False},
            "mlkem768": {"status": "deprecated", "quantum_safe": True},
        }
    }
    engine = PolicyEngine(risk_table=risk_table)
    acceptable, _, _ = engine._is_profile_acceptable(PROFILES["hybrid_standard"], False)
    assert not acceptable

