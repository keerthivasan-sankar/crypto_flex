import hashlib
import json
import re

import pytest

from scripts.generate_release_metadata import build_metadata, main

SHA = "a" * 40
EPOCH = 1794673749
TOOLS = {"pip": "26.2.1", "build": "1.6.0", "setuptools": "84.0.0", "wheel": "0.48.0"}


def _dist(tmp_path, wheels=1, sdists=1):
    d = tmp_path / "dist"
    d.mkdir()
    for i in range(wheels):
        (d / f"pkg-0.1.{i}-py3-none-any.whl").write_bytes(b"wheel%d" % i)
    for i in range(sdists):
        (d / f"pkg-0.1.{i}.tar.gz").write_bytes(b"sdist%d" % i)
    return d


def _sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _validate(meta, resolved_sha, wheel, sdist):
    """Mirror of the checks in .github/workflows/verify-reproducibility.yml."""
    for field in ("commit_sha", "source_date_epoch", "python_version",
                  "pinned_tools", "wheel_sha256", "sdist_sha256"):
        assert field in meta
    assert re.fullmatch(r"[0-9a-f]{40}", meta["commit_sha"])
    assert isinstance(meta["source_date_epoch"], int) and meta["source_date_epoch"] >= 0
    for tool, version in TOOLS.items():
        assert meta["pinned_tools"].get(tool) == version
    for key in ("wheel_sha256", "sdist_sha256"):
        assert re.fullmatch(r"[0-9a-f]{64}", meta[key])
    assert meta["commit_sha"] == resolved_sha
    assert _sha(wheel) == meta["wheel_sha256"]
    assert _sha(sdist) == meta["sdist_sha256"]


def test_metadata_passes_workflow_validation(tmp_path):
    d = _dist(tmp_path)
    meta = build_metadata(d, SHA, EPOCH, tools=TOOLS, python_version="3.11.0")
    _validate(meta, SHA, next(d.glob("*.whl")), next(d.glob("*.tar.gz")))


@pytest.mark.parametrize("wheels,sdists", [(2, 1), (1, 2), (0, 1), (1, 0)])
def test_requires_exactly_one_of_each(tmp_path, wheels, sdists):
    with pytest.raises(ValueError):
        build_metadata(_dist(tmp_path, wheels, sdists), SHA, EPOCH, tools=TOOLS)


@pytest.mark.parametrize("sha", ["abc", "A" * 40, "g" * 40, "a" * 41])
def test_rejects_bad_commit_sha(tmp_path, sha):
    with pytest.raises(ValueError):
        build_metadata(_dist(tmp_path), sha, EPOCH, tools=TOOLS)


@pytest.mark.parametrize("epoch", [-1, True, 1.5])
def test_rejects_bad_epoch(tmp_path, epoch):
    with pytest.raises(ValueError):
        build_metadata(_dist(tmp_path), SHA, epoch, tools=TOOLS)


def test_hash_changes_when_artifact_changes(tmp_path):
    d = _dist(tmp_path)
    before = build_metadata(d, SHA, EPOCH, tools=TOOLS)
    next(d.glob("*.whl")).write_bytes(b"tampered")
    after = build_metadata(d, SHA, EPOCH, tools=TOOLS)
    assert before["wheel_sha256"] != after["wheel_sha256"]


def test_cli_writes_metadata_json(tmp_path, monkeypatch):
    import scripts.generate_release_metadata as gen
    monkeypatch.setattr(gen, "installed_tool_versions", lambda: dict(TOOLS))
    d = _dist(tmp_path)
    rc = main(["--dist-dir", str(d), "--commit-sha", SHA, "--source-date-epoch", str(EPOCH)])
    assert rc == 0
    meta = json.loads((d / "metadata.json").read_text(encoding="utf-8"))
    assert set(meta["pinned_tools"]) == set(TOOLS)
    assert meta["source_date_epoch"] == EPOCH


def test_cli_fails_on_missing_artifacts(tmp_path):
    d = _dist(tmp_path, wheels=0)
    assert main(["--dist-dir", str(d), "--commit-sha", SHA, "--source-date-epoch", "1"]) == 1