"""Tests for the policy risk‑table schema validation.

The :class:`cryptoflex.policy.PolicyEngine` validates the structure of the
risk table during initialisation. These tests exercise the validation logic
directly by providing a variety of invalid ``risk_table`` structures and wrong
top-level data types, asserting that a :class:`ValueError` is raised with an
appropriate message.

Only the validation behaviour is exercised – the test does **not** depend on
any external files or network access.
"""

import pytest

from cryptoflex.policy import PolicyEngine


def _valid_risk_table():
    """Return a minimal but valid risk‑table dictionary.

    The structure mirrors the real ``algorithm_status.json`` but contains only
    the required fields for a single dummy algorithm.
    """
    return {
        "table_version": "1.0",
        "note": "A test note string",
        "algorithms": {
            "dummy_algo": {
                "status": "approved",
                "quantum_safe": False,
                "notes": "Algorithm note string",
            }
        },
    }


def test_valid_risk_table_passes():
    """A correct risk‑table should not raise during validation."""
    PolicyEngine(risk_table=_valid_risk_table())


def test_empty_algorithms_dict_is_valid():
    """An empty algorithms dictionary is valid (no minimum entry requirement)."""
    PolicyEngine(risk_table={"algorithms": {}})


def test_bundled_risk_table_loads_successfully():
    """Default initialization with bundled algorithm_status.json must succeed."""
    engine = PolicyEngine()
    assert "algorithms" in engine.risk_table


def test_forward_compatibility_extra_fields_allowed():
    """Unknown extra fields should be allowed for forward compatibility."""
    table = _valid_risk_table()
    table["future_top_level_field"] = {"some": "data"}
    table["algorithms"]["dummy_algo"]["future_algo_field"] = 12345
    PolicyEngine(risk_table=table)


@pytest.mark.parametrize(
    "bad_table,expected_msg",
    [
        ("not_a_dict", "Risk table must be a dictionary object"),
        (12345, "Risk table must be a dictionary object"),
        ({}, "Risk table missing required 'algorithms' field"),
        ({"table_version": 1, "algorithms": {}}, "'table_version' must be a string"),
        ({"note": 123, "algorithms": {}}, "'note' must be a string"),
        ({"table_version": "1.0", "algorithms": []}, "'algorithms' must be a dictionary object"),
        (
            {"table_version": "1.0", "algorithms": {"a": "not a dict"}},
            "Algorithm entry 'a' must be an object",
        ),
        (
            {"table_version": "1.0", "algorithms": {"a": {"quantum_safe": True}}},
            "Algorithm 'a' missing required 'status' field",
        ),
        (
            {"table_version": "1.0", "algorithms": {"a": {"status": "unknown", "quantum_safe": True}}},
            "Algorithm 'a' has invalid status 'unknown'",
        ),
        (
            {"table_version": "1.0", "algorithms": {"a": {"status": "approved"}}},
            "Algorithm 'a' missing required 'quantum_safe' field",
        ),
        (
            {"table_version": "1.0", "algorithms": {"a": {"status": "approved", "quantum_safe": "yes"}}},
            "Algorithm 'a' quantum_safe must be boolean",
        ),
        (
            {"table_version": "1.0", "algorithms": {"a": {"status": "approved", "quantum_safe": True, "notes": 123}}},
            "Algorithm 'a' notes must be a string",
        ),
    ],
)
def test_invalid_risk_tables(bad_table, expected_msg):
    """Each malformed table should raise a ``ValueError`` with a helpful message."""
    with pytest.raises(ValueError) as excinfo:
        PolicyEngine(risk_table=bad_table)
    assert expected_msg in str(excinfo.value)
