#!/usr/bin/env python3
"""Write ``metadata.json`` next to the release artefacts.

The file records what ``.github/workflows/verify-reproducibility.yml``
validates: commit SHA, SOURCE_DATE_EPOCH, Python version, pinned tool
versions and the SHA-256 of the single wheel and single sdist.
Tool versions are read from the interpreter that runs this script, so run
it with the build environment's Python.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import platform
import re
import sys
from importlib import metadata
from pathlib import Path

TOOLS = ("pip", "build", "setuptools", "wheel")
_SHA_RE = re.compile(r"[0-9a-f]{40}")


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for block in iter(lambda: handle.read(65536), b""):
            digest.update(block)
    return digest.hexdigest()


def _single(dist_dir: Path, suffix: str) -> Path:
    matches = sorted(p for p in dist_dir.iterdir() if p.is_file() and p.name.endswith(suffix))
    if len(matches) != 1:
        raise ValueError(f"expected exactly one *{suffix} in {dist_dir}, found {len(matches)}")
    return matches[0]


def installed_tool_versions() -> dict[str, str]:
    return {tool: metadata.version(tool) for tool in TOOLS}


def build_metadata(
    dist_dir: Path,
    commit_sha: str,
    source_date_epoch: int,
    tools: dict[str, str] | None = None,
    python_version: str | None = None,
) -> dict:
    if not _SHA_RE.fullmatch(commit_sha):
        raise ValueError("commit_sha must be a 40-character lowercase hex string")
    if isinstance(source_date_epoch, bool) or not isinstance(source_date_epoch, int) or source_date_epoch < 0:
        raise ValueError("source_date_epoch must be a non-negative integer")
    dist_dir = Path(dist_dir)
    wheel = _single(dist_dir, ".whl")
    sdist = _single(dist_dir, ".tar.gz")
    return {
        "commit_sha": commit_sha,
        "source_date_epoch": source_date_epoch,
        "python_version": python_version or platform.python_version(),
        "pinned_tools": tools if tools is not None else installed_tool_versions(),
        "wheel_sha256": sha256_file(wheel),
        "sdist_sha256": sha256_file(sdist),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dist-dir", required=True, type=Path)
    parser.add_argument("--commit-sha", required=True)
    parser.add_argument("--source-date-epoch", required=True, type=int)
    args = parser.parse_args(argv)
    try:
        meta = build_metadata(args.dist_dir, args.commit_sha, args.source_date_epoch)
    except (ValueError, metadata.PackageNotFoundError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    out = args.dist_dir / "metadata.json"
    out.write_bytes((json.dumps(meta, indent=2, sort_keys=True) + "\n").encode("utf-8"))
    print(f"wrote {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())