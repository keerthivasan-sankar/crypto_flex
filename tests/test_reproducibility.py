import sys
from pathlib import Path
from unittest import mock
import pytest
import json
import tarfile

# Add the scripts directory to the path so we can import the verifier
repo_root = Path(__file__).resolve().parents[1]
scripts_dir = repo_root / "scripts"
if str(scripts_dir) not in sys.path:
    sys.path.insert(0, str(scripts_dir))

import verify_reproducibility

# Helper to create a dummy BuildResult dict
def make_build_result(wheel_hash="abc", wheel_size=100, sdist_hash="def", sdist_size=200):
    return {
        "build_id": 1,
        "environment": "fresh_isolated_venv",
        "python_executable": "/fake/python",
        "sys_prefix": "/fake/prefix",
        "sys_base_prefix": "/fake/base",
        "wheel": {
            "filename": "fake-0.1.0-py3-none-any.whl",
            "hash": wheel_hash,
            "size": wheel_size,
        },
        "sdist": {
            "raw": {
                "filename": "fake-0.1.0.tar.gz",
                "hash": sdist_hash,
                "size": sdist_size,
            },
            "normalized": {
                "filename": "fake-0.1.0_normalized.tar.gz",
                "hash": "norm" + sdist_hash,
                "size": sdist_size - 10,
            }
        }
    }


def make_reference_dict(wheel_hash="abc", wheel_size=100, sdist_hash="def", sdist_size=200):
    return {
        "wheel": {
            "filename": "ref.whl",
            "hash": wheel_hash,
            "size": wheel_size
        },
        "sdist": {
            "filename": "ref.tar.gz",
            "hash": sdist_hash,
            "size": sdist_size
        }
    }


def test_matching_artifacts_report_reproducible():
    b1 = make_build_result(wheel_hash="w1", sdist_hash="s1")
    b2 = make_build_result(wheel_hash="w1", sdist_hash="s1")
    verdict = verify_reproducibility.compute_verdict([b1, b2], reference=None)
    assert verdict["wheel_reproducible"] is True
    assert verdict["raw_sdist_reproducible"] is True
    assert verdict["outcome"] == "REPRODUCIBLE"


def test_mismatching_wheel_reports_non_reproducible():
    b1 = make_build_result(wheel_hash="w1", sdist_hash="s1")
    b2 = make_build_result(wheel_hash="w2", sdist_hash="s1")
    verdict = verify_reproducibility.compute_verdict([b1, b2], reference=None)
    assert verdict["wheel_reproducible"] is False
    assert verdict["raw_sdist_reproducible"] is True
    assert verdict["outcome"] == "NON_REPRODUCIBLE"


def test_mismatching_sdist_reports_non_reproducible():
    b1 = make_build_result(wheel_hash="w1", sdist_hash="s1")
    b2 = make_build_result(wheel_hash="w1", sdist_hash="s2")
    verdict = verify_reproducibility.compute_verdict([b1, b2], reference=None)
    assert verdict["wheel_reproducible"] is True
    assert verdict["raw_sdist_reproducible"] is False
    assert verdict["outcome"] == "NON_REPRODUCIBLE"


def test_reference_parity_pass():
    b1 = make_build_result(wheel_hash="w1", sdist_hash="s1")
    b2 = make_build_result(wheel_hash="w1", sdist_hash="s1")
    ref = make_reference_dict(wheel_hash="w1", sdist_hash="s1")
    verdict = verify_reproducibility.compute_verdict([b1, b2], reference=ref)
    
    assert verdict["outcome"] == "REPRODUCIBLE"
    assert verdict["reference_parity"] is True
    assert verdict["reference_details"]["wheel_parity"] is True
    assert verdict["reference_details"]["sdist_parity"] is True


def test_reference_parity_fail():
    b1 = make_build_result(wheel_hash="w1", sdist_hash="s1")
    b2 = make_build_result(wheel_hash="w1", sdist_hash="s1")
    ref = make_reference_dict(wheel_hash="w2", sdist_hash="s1") # wheel mismatch
    verdict = verify_reproducibility.compute_verdict([b1, b2], reference=ref)
    
    assert verdict["outcome"] == "NON_REPRODUCIBLE"
    assert verdict["reference_parity"] is False
    assert verdict["reference_details"]["wheel_parity"] is False
    assert verdict["reference_details"]["sdist_parity"] is True


def test_missing_reference_wheel(tmp_path):
    # create only sdist
    (tmp_path / "foo.tar.gz").write_text("fake sdist")
    
    with pytest.raises(RuntimeError, match="No wheel \\(.whl\\) artifact found"):
        verify_reproducibility.load_reference_artifacts(tmp_path)


def test_missing_reference_sdist(tmp_path):
    # create only wheel
    (tmp_path / "foo.whl").write_text("fake wheel")
    
    with pytest.raises(RuntimeError, match="No sdist \\(.tar.gz\\) artifact found"):
        verify_reproducibility.load_reference_artifacts(tmp_path)


@mock.patch("verify_reproducibility.run_cmd")
def test_wrong_tool_version(mock_run_cmd, tmp_path):
    # Mocking run_cmd to simulate env creation and package listing
    def side_effect(cmd, *args, **kwargs):
        if "venv" in cmd:
            return 0, "", ""
        if "install" in cmd:
            return 0, "", ""
        if "-c" in cmd:
            # sys.executable, sys.prefix, sys.base_prefix
            return 0, '["/fake/python", "/fake/env", "/fake/base"]', ""
        if "list" in cmd:
            # return wrong version for setuptools
            wrong_list = [
                {"name": "pip", "version": "26.2.1"},
                {"name": "setuptools", "version": "83.0.0"}, # Wrong
                {"name": "wheel", "version": "0.48.0"},
                {"name": "build", "version": "1.6.0"},
            ]
            return 0, json.dumps(wrong_list), ""
        return 0, "", ""
        
    mock_run_cmd.side_effect = side_effect
    
    # We also have to mock Path.exists for the python executable since it won't be created
    with mock.patch("pathlib.Path.exists", return_value=True):
        with pytest.raises(RuntimeError, match="Package setuptools version mismatch"):
            verify_reproducibility.prepare_fresh_build_environment(tmp_path, sys.executable)


@mock.patch("verify_reproducibility.run_cmd")
def test_source_ref_resolution(mock_run_cmd):
    expected_sha = "9bad1af777308824ddc35f8fb4d5fe49d09c0d70"
    
    def side_effect(cmd, *args, **kwargs):
        if "rev-list" in cmd:
            return 0, expected_sha, ""
        if "log" in cmd:
            return 0, "1789881553", ""
        return 1, "", "Unknown command"
        
    mock_run_cmd.side_effect = side_effect

    resolved_sha, commit_ts = verify_reproducibility.resolve_source_ref(repo_root, "v0.5.3")
    
    assert resolved_sha == expected_sha
    assert commit_ts == 1789881553


@pytest.mark.slow
@mock.patch("verify_reproducibility.prepare_fresh_build_environment")
def test_timestamp_mismatch_causes_different_hash(mock_prepare, tmp_path):
    """
    Test that modifying SOURCE_DATE_EPOCH actually changes the sdist hash.
    Instead of running a full build (which is slow and complex), we'll test that
    the normalization function produces different hashes for different timestamps.
    """
    # Create a dummy tar.gz file
    dummy_sdist = tmp_path / "dummy.tar.gz"
    with tarfile.open(dummy_sdist, "w:gz") as tf:
        dummy_member = tmp_path / "file.txt"
        dummy_member.write_text("hello world")
        tf.add(dummy_member, arcname="file.txt")
        
    hash1, size1, norm1 = verify_reproducibility.normalize_sdist_copy(dummy_sdist, 1000)
    hash2, size2, norm2 = verify_reproducibility.normalize_sdist_copy(dummy_sdist, 2000)
    
    assert hash1 != hash2
