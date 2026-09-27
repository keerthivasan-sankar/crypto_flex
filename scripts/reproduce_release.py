#!/usr/bin/env python3
"""reproduce_release.py
====================

Independent reproduction helper for CryptoFlex package releases.

Allows an independent machine/environment to rebuild release artifacts from a
clean git archive and verify artifact SHA-256 checksums against reference
release artifacts using a fresh isolated virtual environment with the pinned
build toolchain (pip==26.2.1, build==1.6.0, setuptools==84.0.0, wheel==0.48.0).

Usage:
    python scripts/reproduce_release.py [--target v0.5.4] [--reference-dir path/to/dist] [--output-json out.json]
"""

from __future__ import annotations

import argparse
import json
import os
import platform
import shutil
import sys
import tempfile
from pathlib import Path

# Ensure repository root is on sys.path
REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from scripts.verify_reproducibility import (
    PINNED_TOOLS,
    extract_source_tree,
    load_reference_artifacts,
    prepare_fresh_build_environment,
    resolve_source_ref,
    run_cmd,
    sha256_file,
)

# Official published reference artifact metadata for known releases
OFFICIAL_RELEASE_REFERENCES: dict[str, dict] = {
    "v0.5.4": {
        "commit_sha": "72ea01776b6d8390fb4c3993724853d7c50c8543",
        "commit_timestamp": 1790428894,
        "wheel": {
            "filename": "cryptoflex-0.5.4-py3-none-any.whl",
            "hash": "97c74a58487766c987d4be413d7905bfa9101ccdcbceeec64c9df7406aa62794",
            "size": 43924,
        },
        "sdist": {
            "filename": "cryptoflex-0.5.4.tar.gz",
            "hash": "91c8f595cbcba6bb82ee71fd4997f01908889d3346f0e0bdef8da653a697763f",
            "size": 64885,
        },
    }
}


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Independently reproduce and verify CryptoFlex release artifacts."
    )
    parser.add_argument(
        "--target",
        default="v0.5.4",
        help="Release tag, branch, or commit SHA to reproduce (defaults to 'v0.5.4').",
    )
    parser.add_argument(
        "--reference-dir",
        default=None,
        help=(
            "Path to a directory containing reference artifacts (.whl and .tar.gz) "
            "to compare against. If omitted and --target matches a known release, "
            "official published release hashes are used."
        ),
    )
    parser.add_argument(
        "--output-json",
        default=None,
        help="Optional file path to write machine-readable JSON summary.",
    )
    return parser.parse_args(argv)


def get_environment_metadata(host_python: str) -> dict:
    """Collect host environment details for independent reproduction audit logs."""
    return {
        "os": platform.system(),
        "os_release": platform.release(),
        "os_version": platform.version(),
        "platform": platform.platform(),
        "architecture": platform.machine(),
        "python_version": platform.python_version(),
        "python_executable": host_python,
    }


def reproduce_build(
    repo_root: Path,
    target_ref: str,
    reference_dir: Path | None = None,
    host_python: str | None = None,
) -> dict:
    """Execute reproduction build and comparison.

    Returns a summary dictionary.
    """
    python_exe = host_python or sys.executable
    env_metadata = get_environment_metadata(python_exe)

    commit_sha, commit_ts = resolve_source_ref(repo_root, target_ref)

    # Resolve reference metadata if available
    reference = None
    if reference_dir is not None:
        reference = load_reference_artifacts(reference_dir)
    elif target_ref in OFFICIAL_RELEASE_REFERENCES:
        ref_entry = OFFICIAL_RELEASE_REFERENCES[target_ref]
        reference = {
            "wheel": ref_entry["wheel"],
            "sdist": ref_entry["sdist"],
        }

    tmp_dir = Path(tempfile.mkdtemp(prefix="cryptoflex_reproduce_"))
    try:
        src_dir = tmp_dir / "crypto_flex"
        extract_source_tree(repo_root, commit_sha, src_dir)

        # Fresh isolated build environment with pinned toolchain
        build_env = prepare_fresh_build_environment(tmp_dir, python_exe)
        build_python = build_env["python_executable"]

        # Run PEP 517 build with deterministic timestamp
        build_os_env = os.environ.copy()
        build_os_env["SOURCE_DATE_EPOCH"] = str(commit_ts)

        rc, out, err = run_cmd(
            [
                build_python,
                "-m",
                "build",
                "--sdist",
                "--wheel",
            ],
            cwd=str(src_dir),
            env=build_os_env,
        )
        if rc != 0:
            raise RuntimeError(f"Build failed with exit code {rc}:\n{err}\n{out}")

        dist_dir = src_dir / "dist"
        wheels = list(dist_dir.glob("*.whl"))
        sdists = list(dist_dir.glob("*.tar.gz"))

        if not wheels:
            raise RuntimeError("Build produced no wheel (.whl) artifact")
        if not sdists:
            raise RuntimeError("Build produced no sdist (.tar.gz) artifact")

        wheel_path = wheels[0]
        sdist_path = sdists[0]

        built_artifacts = {
            "wheel": {
                "filename": wheel_path.name,
                "hash": sha256_file(wheel_path),
                "size": wheel_path.stat().st_size,
            },
            "sdist": {
                "filename": sdist_path.name,
                "hash": sha256_file(sdist_path),
                "size": sdist_path.stat().st_size,
            },
        }

        # Compare against reference if available
        comparison = None
        matches = None
        if reference is not None:
            whl_match = built_artifacts["wheel"]["hash"] == reference["wheel"]["hash"]
            sdist_match = built_artifacts["sdist"]["hash"] == reference["sdist"]["hash"]
            matches = whl_match and sdist_match
            comparison = {
                "reference_source": str(reference_dir) if reference_dir else f"official_{target_ref}_metadata",
                "reference_wheel": reference["wheel"],
                "reference_sdist": reference["sdist"],
                "wheel_matches": whl_match,
                "sdist_matches": sdist_match,
                "all_match": matches,
            }

        return {
            "target": target_ref,
            "resolved_commit_sha": commit_sha,
            "commit_timestamp": commit_ts,
            "environment": env_metadata,
            "pinned_toolchain": PINNED_TOOLS,
            "built_artifacts": built_artifacts,
            "comparison": comparison,
            "status": "SUCCESS" if (matches is None or matches) else "MISMATCH",
        }
    finally:
        shutil.rmtree(tmp_dir, ignore_errors=True)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    repo_root = REPO_ROOT
    host_python = sys.executable

    print(f"=== CryptoFlex Independent Reproduction Helper ===")
    print(f"Target Ref:  {args.target}")
    print(f"Host Python: {host_python} ({platform.python_version()} on {platform.system()} {platform.machine()})")

    ref_dir = Path(args.reference_dir) if args.reference_dir else None

    try:
        summary = reproduce_build(repo_root, args.target, ref_dir, host_python)
    except Exception as e:
        print(f"\n[ERROR] Reproduction failed: {e}", file=sys.stderr)
        err_str = str(e).lower()
        if "ssl" in err_str or "certificate" in err_str:
            print(
                "\n[NOTE] TLS certificate verification failed during build environment setup.\n"
                "CryptoFlex requires genuine HTTPS certificate verification and does not allow\n"
                "--trusted-host or TLS bypasses. Please ensure your machine's system CA certificate\n"
                "bundle is properly installed and recognized.",
                file=sys.stderr,
            )
        return 1

    print("\n=== Built Artifacts ===")
    whl = summary["built_artifacts"]["wheel"]
    sdist = summary["built_artifacts"]["sdist"]
    print(f"  Wheel: {whl['filename']} ({whl['size']} bytes)")
    print(f"         SHA-256: {whl['hash']}")
    print(f"  Sdist: {sdist['filename']} ({sdist['size']} bytes)")
    print(f"         SHA-256: {sdist['hash']}")

    if summary["comparison"]:
        comp = summary["comparison"]
        print("\n=== Reference Comparison ===")
        print(f"  Reference Source: {comp['reference_source']}")
        print(f"  Wheel Match:      {'PASS' if comp['wheel_matches'] else 'FAIL'}")
        print(f"  Sdist Match:      {'PASS' if comp['sdist_matches'] else 'FAIL'}")
        print(f"  Verdict:          {'MATCH' if comp['all_match'] else 'MISMATCH'}")

    print("\n--- MACHINE-READABLE SUMMARY ---")
    json_output = json.dumps(summary, indent=2)
    print(json_output)

    if args.output_json:
        out_p = Path(args.output_json)
        out_p.write_text(json_output, encoding="utf-8")
        print(f"\nSummary written to: {out_p}")

    return 0 if summary["status"] == "SUCCESS" else 1


if __name__ == "__main__":
    sys.exit(main())
