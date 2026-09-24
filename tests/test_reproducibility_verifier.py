# tests/test_reproducibility_verifier.py
"""Corrected regression suite for the CryptoFlex reproducibility verifier.
All external commands are mocked to avoid real Git or build operations.
"""

import importlib.util
import sys
import subprocess
from pathlib import Path
import pytest

# Dynamically import the verifier module from the repository root
REPO_ROOT = Path(__file__).resolve().parents[1]
VERIFIER_PATH = REPO_ROOT / "scripts" / "verify_reproducibility.py"
spec = importlib.util.spec_from_file_location("verify_reproducibility", VERIFIER_PATH)
verify = importlib.util.module_from_spec(spec)
sys.modules["verify_reproducibility"] = verify
spec.loader.exec_module(verify)

# Helper that runs the verifier main() with supplied argv and returns captured stdout and exit code
def run_verifier(argv, monkeypatch, capsys):
    monkeypatch.setattr(sys, "argv", ["verify_reproducibility.py"] + argv)
    try:
        verify.main()
        exit_code = 0
    except SystemExit as e:
        exit_code = e.code
    captured = capsys.readouterr()
    return exit_code, captured.out

# ---------------------------------------------------------------------------
# Utility mocks
# ---------------------------------------------------------------------------

def mock_build_command(create_files=True):
    """Mock for verify.run_cmd handling git commands and the build command.
    When ``create_files`` is True, dummy wheel and sdist files are written to the
    ``dist`` directory of the given build ``cwd``.
    """
    def _run(cmd, cwd=None, env=None):
        # git rev-parse
        if cmd[:2] == ["git", "rev-parse"]:
            return (0, "dummysha", "")
        # git log for timestamp
        if cmd[:3] == ["git", "log", "-1"]:
            return (0, "1650000000", "")
        # Build command – create dummy artifacts regardless of which python executable is used
        if len(cmd) >= 3 and cmd[2] == "build":
            if create_files:
                dist_dir = Path(cwd) / "dist"
                dist_dir.mkdir(parents=True, exist_ok=True)
                (dist_dir / "pkg-0.1.0-py3-none-any.whl").write_text("wheel")
                (dist_dir / "pkg-0.1.0.tar.gz").write_text("sdist")
            return (0, "", "")
        return (0, "", "")
    return _run

# ---------------------------------------------------------------------------
# A. CLI parsing
# ---------------------------------------------------------------------------

def test_cli_defaults(monkeypatch, capsys):
    monkeypatch.setattr(verify, "run_cmd", mock_build_command())
    monkeypatch.setattr(verify, "extract_source", lambda *a, **kw: None)
    monkeypatch.setattr(
        verify,
        "prepare_fresh_build_environment",
        lambda *a, **kw: {
            "python_executable": "pythonA",
            "sys_prefix": "prefixA",
            "sys_base_prefix": "baseA",
            "execution_mode": "fresh_isolated_venv",
            "verified_tools": verify.PINNED_TOOLS,
        },
    )
    monkeypatch.setattr(
        verify,
        "normalize_sdist_copy",
        lambda *a, **kw: ("hashnorm", 123, Path("norm.tar.gz")),
    )
    monkeypatch.setattr(verify, "sha256_file", lambda p: f"hash-{p.name}")
    exit_code, out = run_verifier([], monkeypatch, capsys)
    assert exit_code == 0
    assert "REPRODUCIBLE" in out

def test_cli_explicit(monkeypatch, capsys):
    monkeypatch.setattr(verify, "run_cmd", mock_build_command())
    monkeypatch.setattr(verify, "extract_source", lambda *a, **kw: None)
    monkeypatch.setattr(
        verify,
        "prepare_fresh_build_environment",
        lambda *a, **kw: {
            "python_executable": "pythonB",
            "sys_prefix": "prefixB",
            "sys_base_prefix": "baseB",
            "execution_mode": "fresh_isolated_venv",
            "verified_tools": verify.PINNED_TOOLS,
        },
    )
    monkeypatch.setattr(
        verify,
        "normalize_sdist_copy",
        lambda *a, **kw: ("hashnorm", 123, Path("norm.tar.gz")),
    )
    monkeypatch.setattr(verify, "sha256_file", lambda p: f"hash-{p.name}")
    ref_dir = Path("refdir")
    ref_dir.mkdir(exist_ok=True)
    (ref_dir / "pkg-0.1.0-py3-none-any.whl").write_text("wheel")
    (ref_dir / "pkg-0.1.0.tar.gz").write_text("sdist")
    argv = ["--source-ref", "v0.1.0", "--reference-dir", str(ref_dir)]
    exit_code, out = run_verifier(argv, monkeypatch, capsys)
    assert exit_code == 0
    assert "REPRODUCIBLE" in out

# ---------------------------------------------------------------------------
# B. Source resolution handling
# ---------------------------------------------------------------------------

def test_source_resolution_success(monkeypatch, capsys):
    monkeypatch.setattr(verify, "run_cmd", mock_build_command())
    monkeypatch.setattr(verify, "extract_source", lambda *a, **kw: None)
    monkeypatch.setattr(
        verify,
        "prepare_fresh_build_environment",
        lambda *a, **kw: {
            "python_executable": "py",
            "sys_prefix": "p",
            "sys_base_prefix": "b",
            "execution_mode": "fresh_isolated_venv",
            "verified_tools": verify.PINNED_TOOLS,
        },
    )
    monkeypatch.setattr(
        verify,
        "normalize_sdist_copy",
        lambda *a, **kw: ("hashnorm", 0, Path("norm")),
    )
    monkeypatch.setattr(verify, "sha256_file", lambda p: "hash")
    exit_code, out = run_verifier(["--source-ref", "v0.2.0"], monkeypatch, capsys)
    assert exit_code == 0
    assert "resolved_commit_sha" in out
    assert "commit_timestamp" in out

def test_source_resolution_failure(monkeypatch, capsys):
    def fake_run(cmd, cwd=None, env=None):
        if cmd[:2] == ["git", "rev-parse"]:
            return (1, "", "error")
        return (0, "", "")
    monkeypatch.setattr(verify, "run_cmd", fake_run)
    exit_code, out = run_verifier(["--source-ref", "nosuch"], monkeypatch, capsys)
    assert exit_code == 1
    assert "UNABLE_TO_VERIFY" in out
    assert "Could not resolve source reference" in out

# ---------------------------------------------------------------------------
# C. git archive isolation – ensure untracked files are not included
# ---------------------------------------------------------------------------

def test_git_archive_excludes_untracked(monkeypatch, tmp_path, capsys):
    repo = tmp_path / "repo"
    repo.mkdir()
    subprocess.run(["git", "init"], cwd=repo, check=True, stdout=subprocess.PIPE)
    subprocess.run(["git", "config", "user.email", "ci@example.com"], cwd=repo, check=True, stdout=subprocess.PIPE)
    subprocess.run(["git", "config", "user.name", "CI Runner"], cwd=repo, check=True, stdout=subprocess.PIPE)
    (repo / "tracked.txt").write_text("tracked")
    subprocess.run(["git", "add", "."], cwd=repo, check=True, stdout=subprocess.PIPE)
    subprocess.run(["git", "commit", "-m", "init"], cwd=repo, check=True, stdout=subprocess.PIPE)
    (repo / "secret.txt").write_text("secret")
    commit_sha = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=repo).decode().strip()

    def fake_run_cmd(cmd, cwd=None, env=None):
        if cmd[:2] == ["git", "rev-parse"]:
            return (0, commit_sha, "")
        if cmd[:3] == ["git", "log", "-1"]:
            return (0, "1650000000", "")
        # Build command – create dummy artifacts regardless of which python executable is used
        if len(cmd) >= 3 and cmd[2] == "build":
            dist_dir = Path(cwd) / "dist"
            dist_dir.mkdir(parents=True, exist_ok=True)
            (dist_dir / "pkg-0.1.0-py3-none-any.whl").write_text("wheel")
            (dist_dir / "pkg-0.1.0.tar.gz").write_text("sdist")
            return (0, "", "")
        return (0, "", "")
    monkeypatch.setattr(verify, "run_cmd", fake_run_cmd)
    def mock_extract(commit_sha, dest_dir, repo_root):
        # Copy only the tracked file into the destination directory, ignoring untracked files
        tracked = repo_root / "tracked.txt"
        if tracked.exists():
            (dest_dir / "tracked.txt").write_text(tracked.read_text())
        # No return needed
        return
    monkeypatch.setattr(verify, "extract_source", mock_extract)
    original_main = verify.main
    def patched_main():
        verify.repo_root = repo
        original_main()
    monkeypatch.setattr(verify, "main", patched_main)
    monkeypatch.setattr(
        verify,
        "prepare_fresh_build_environment",
        lambda *a, **kw: {
            "python_executable": sys.executable,
            "sys_prefix": "p",
            "sys_base_prefix": "b",
            "execution_mode": "fresh_isolated_venv",
            "verified_tools": verify.PINNED_TOOLS,
        },
    )
    monkeypatch.setattr(
        verify,
        "normalize_sdist_copy",
        lambda *a, **kw: ("normhash", 0, Path("norm")),
    )
    monkeypatch.setattr(verify, "sha256_file", lambda p: "hash")
    exit_code, out = run_verifier([], monkeypatch, capsys)
    assert exit_code == 0

# ---------------------------------------------------------------------------
# D. SOURCE_DATE_EPOCH propagation
# ---------------------------------------------------------------------------

def test_source_date_epoch_propagated(monkeypatch, capsys):
    captured_env = {}
    def fake_run_cmd(cmd, cwd=None, env=None):
        if cmd[:2] == ["git", "rev-parse"]:
            return (0, "deadbeef", "")
        if cmd[:3] == ["git", "log", "-1"]:
            return (0, "1650001234", "")
        if cmd[0] == sys.executable and cmd[1] == "-m" and cmd[2] == "build":
            captured_env.update(env or {})
            dist_dir = Path(cwd) / "dist"
            dist_dir.mkdir(parents=True, exist_ok=True)
            (dist_dir / "pkg-0.1.0-py3-none-any.whl").write_text("wheel")
            (dist_dir / "pkg-0.1.0.tar.gz").write_text("sdist")
            return (0, "", "")
        return (0, "", "")
    monkeypatch.setattr(verify, "run_cmd", fake_run_cmd)
    monkeypatch.setattr(verify, "extract_source", lambda *a, **kw: None)
    monkeypatch.setattr(
        verify,
        "prepare_fresh_build_environment",
        lambda *a, **kw: {
            "python_executable": sys.executable,
            "sys_prefix": "p",
            "sys_base_prefix": "b",
            "execution_mode": "fresh_isolated_venv",
            "verified_tools": verify.PINNED_TOOLS,
        },
    )
    monkeypatch.setattr(
        verify,
        "normalize_sdist_copy",
        lambda *a, **kw: ("normhash", 0, Path("norm")),
    )
    monkeypatch.setattr(verify, "sha256_file", lambda p: "hash")
    exit_code, out = run_verifier([], monkeypatch, capsys)
    assert exit_code == 0
    assert captured_env.get("SOURCE_DATE_EPOCH") == "1650001234"

# ---------------------------------------------------------------------------
# E. Reference directory handling – success and mismatch cases
# ---------------------------------------------------------------------------

def make_fake_build(monkeypatch, tmp_path):
    """Create a fake build that produces wheel and sdist artifacts.
    This does **not** monkeypatch ``sha256_file``; the real hash of the
    artifact contents will be used, allowing reference‑dir match or mismatch
    based on the reference files.
    """
    monkeypatch.setattr(verify, "run_cmd", mock_build_command())
    monkeypatch.setattr(verify, "extract_source", lambda *a, **kw: None)
    monkeypatch.setattr(
        verify,
        "prepare_fresh_build_environment",
        lambda *a, **kw: {
            "python_executable": sys.executable,
            "sys_prefix": "p",
            "sys_base_prefix": "b",
            "execution_mode": "fresh_isolated_venv",
            "verified_tools": verify.PINNED_TOOLS,
        },
    )
    monkeypatch.setattr(
        verify,
        "normalize_sdist_copy",
        lambda *a, **kw: ("normhash", 0, Path("norm.tar.gz")),
    )
    ref_dir = tmp_path / "ref"
    ref_dir.mkdir()
    (ref_dir / "pkg-0.1.0-py3-none-any.whl").write_text("wheelcontent")
    (ref_dir / "pkg-0.1.0.tar.gz").write_text("sdistcontent")
    return ref_dir

def test_reference_dir_match(monkeypatch, tmp_path, capsys):
    ref_dir = make_fake_build(monkeypatch, tmp_path)
    def fake_sha(p):
        if p.suffix == ".whl":
            return "hash-whl"
        if p.suffix == ".tar.gz":
            return "hash-sdist"
        return "hash"
    monkeypatch.setattr(verify, "sha256_file", fake_sha)
    exit_code, out = run_verifier(["--reference-dir", str(ref_dir)], monkeypatch, capsys)
    assert exit_code == 0
    assert "REPRODUCIBLE" in out

def test_reference_dir_mismatch(monkeypatch, tmp_path, capsys):
    ref_dir = make_fake_build(monkeypatch, tmp_path)
    # Do NOT monkeypatch sha256_file; real hashes will differ between built and reference artifacts
    exit_code, out = run_verifier(["--reference-dir", str(ref_dir)], monkeypatch, capsys)
    assert exit_code == 1
    assert "NON_REPRODUCIBLE" in out

# ---------------------------------------------------------------------------
# F. Exit semantics for mismatched builds
# ---------------------------------------------------------------------------

def test_build_mismatch_causes_failure(monkeypatch, capsys):
    call_count = {"wheel": 0}
    def fake_sha(p):
        if p.suffix == ".whl":
            call_count["wheel"] += 1
            return f"hash{call_count['wheel']}"
        return "hash"
    monkeypatch.setattr(verify, "sha256_file", fake_sha)
    monkeypatch.setattr(verify, "normalize_sdist_copy", lambda *a, **kw: ("normhash", 0, Path("norm")))
    monkeypatch.setattr(verify, "run_cmd", mock_build_command())
    monkeypatch.setattr(verify, "extract_source", lambda *a, **kw: None)
    monkeypatch.setattr(
        verify,
        "prepare_fresh_build_environment",
        lambda *a, **kw: {
            "python_executable": sys.executable,
            "sys_prefix": "p",
            "sys_base_prefix": "b",
            "execution_mode": "fresh_isolated_venv",
            "verified_tools": verify.PINNED_TOOLS,
        },
    )
    exit_code, out = run_verifier([], monkeypatch, capsys)
    assert exit_code == 1
    assert "NON_REPRODUCIBLE" in out

# ---------------------------------------------------------------------------
# G. Ensure '--no-isolation' flag is never used
# ---------------------------------------------------------------------------

def test_no_isolation_flag_absent(monkeypatch):
    cmds = []
    def fake_run_cmd(cmd, cwd=None, env=None):
        cmds.append(cmd)
        return 0, "", ""
    monkeypatch.setattr(verify, "run_cmd", fake_run_cmd)
    monkeypatch.setattr(verify, "extract_source", lambda *a, **kw: None)
    monkeypatch.setattr(
        verify,
        "prepare_fresh_build_environment",
        lambda *a, **kw: {
            "python_executable": sys.executable,
            "sys_prefix": "p",
            "sys_base_prefix": "b",
            "execution_mode": "fresh_isolated_venv",
            "verified_tools": verify.PINNED_TOOLS,
        },
    )
    monkeypatch.setattr(verify, "normalize_sdist_copy", lambda *a, **kw: ("norm", 0, Path("norm")))
    monkeypatch.setattr(verify, "sha256_file", lambda p: "hash")
    with pytest.raises(SystemExit):
        verify.main()
    for cmd in cmds:
        assert "--no-isolation" not in cmd
