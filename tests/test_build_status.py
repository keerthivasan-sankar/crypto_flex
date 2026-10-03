import pytest
import sys
import subprocess
from pathlib import Path
from scripts.reproduce_release import reproduce_build

def test_build_only_status(tmp_path: Path) -> None:
    """Exercise the BUILD_ONLY path of ``reproduce_build``.

    The function should return ``status == "BUILD_ONLY"`` and ``comparison``
    ``None`` when the target reference resolves to a known commit but no
    reference artifacts are supplied (i.e. ``reference`` remains ``None``).
    """
    repo_root = Path(__file__).parents[1]
    # Resolve the current HEAD commit SHA – this is a valid reference that is
    # not present in ``OFFICIAL_RELEASE_REFERENCES``.
    completed = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=str(repo_root),
        capture_output=True,
        text=True,
        check=True,
    )
    head_sha = completed.stdout.strip()

    result = reproduce_build(
        repo_root=repo_root,
        target_ref=head_sha,
        reference_dir=None,
        host_python=sys.executable,
    )
    assert result["status"] == "BUILD_ONLY"
    assert result["comparison"] is None
