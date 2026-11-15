import os
import shutil
import tempfile
from pathlib import Path
import pytest

from scripts.verify_reproducibility import load_reference_artifacts

def create_artifact(dir_path: Path, name: str):
    (dir_path / name).write_bytes(b"dummy content")

@pytest.fixture
def temp_dir():
    with tempfile.TemporaryDirectory() as td:
        yield Path(td)

def test_single_wheel_and_sdist(temp_dir: Path):
    create_artifact(temp_dir, "example-1.0.0-py3-none-any.whl")
    create_artifact(temp_dir, "example-1.0.0.tar.gz")
    result = load_reference_artifacts(temp_dir)
    assert "wheel" in result and "sdist" in result
    assert result["wheel"]["filename"] == "example-1.0.0-py3-none-any.whl"
    assert result["sdist"]["filename"] == "example-1.0.0.tar.gz"

def test_missing_wheel(temp_dir: Path):
    create_artifact(temp_dir, "example-1.0.0.tar.gz")
    with pytest.raises(RuntimeError) as exc:
        load_reference_artifacts(temp_dir)
    assert "wheel" in str(exc.value).lower()

def test_missing_sdist(temp_dir: Path):
    create_artifact(temp_dir, "example-1.0.0-py3-none-any.whl")
    with pytest.raises(RuntimeError) as exc:
        load_reference_artifacts(temp_dir)
    assert "sdist" in str(exc.value).lower()

def test_multiple_wheels(temp_dir: Path):
    create_artifact(temp_dir, "a.whl")
    create_artifact(temp_dir, "b.whl")
    create_artifact(temp_dir, "example-1.0.0.tar.gz")
    with pytest.raises(RuntimeError) as exc:
        load_reference_artifacts(temp_dir)
    assert "exactly one wheel" in str(exc.value).lower()

def test_multiple_sdists(temp_dir: Path):
    create_artifact(temp_dir, "example-1.0.0-py3-none-any.whl")
    create_artifact(temp_dir, "a.tar.gz")
    create_artifact(temp_dir, "b.tar.gz")
    with pytest.raises(RuntimeError) as exc:
        load_reference_artifacts(temp_dir)
    assert "exactly one sdist" in str(exc.value).lower()
