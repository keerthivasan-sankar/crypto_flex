"""verify_reproducibility.py

Utility to test reproducible builds of the CryptoFlex package.

It performs two independent builds from a specific Git revision (controlled via
``--source-ref``, defaulting to ``HEAD``) using separate temporary source copies
extracted via ``git archive`` and separate fresh virtual build environments
populated with pinned build dependencies (pip==26.2.1, setuptools==84.0.0,
wheel==0.48.0, build==1.6.0).

The script records raw artifact hashes for the wheel and the source distribution
before any normalization. It then optionally normalizes the sdist for diagnostic
reporting.

When ``--reference-dir`` is supplied, the script additionally compares the
independently rebuilt artifacts against the reference artifacts found in that
directory (e.g. the CI-produced ``dist/`` or downloaded published release
artifacts). The local ``dist/`` directory is **never** implicitly consulted.

The script reports one of three outcomes:
  * REPRODUCIBLE – raw wheel and raw sdist are byte-for-byte identical across
    two independent builds (and match the reference artifacts, if supplied).
  * NON_REPRODUCIBLE – artifact SHA-256 checksums differ.
  * UNABLE_TO_VERIFY – the experiment could not be performed (e.g. build failure).
"""

import argparse
import gzip
import hashlib
import io
import json
import os
import shutil
import subprocess
import sys
import tarfile
import tempfile
from pathlib import Path

# Pinned build toolchain specifications
PINNED_TOOLS = {
    "pip": "26.2.1",
    "setuptools": "84.0.0",
    "wheel": "0.48.0",
    "build": "1.6.0",
}


def run_cmd(cmd, cwd=None, env=None):
    """Run a command, returning (returncode, stdout, stderr)."""
    result = subprocess.run(
        cmd,
        cwd=cwd,
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        shell=False,
    )
    return result.returncode, result.stdout.strip(), result.stderr.strip()


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()


def normalize_sdist_copy(sdist_path: Path, target_mtime: int) -> tuple[str, int, Path]:
    """Create a normalized copy of the sdist without mutating the original file.
    Returns (sha256_hash, file_size_bytes, normalized_path).

    This is a DIAGNOSTIC-ONLY operation. The primary reproducibility verdict
    uses raw (un-normalized) SHA-256 hashes.
    """
    with tarfile.open(sdist_path, "r:gz") as tf_in:
        members = tf_in.getmembers()
        members.sort(key=lambda m: m.name)

        tar_out_buf = io.BytesIO()
        with tarfile.open(fileobj=tar_out_buf, mode="w:", format=tarfile.PAX_FORMAT) as tf_out:
            for member in members:
                m = tarfile.TarInfo()
                m.name = member.name
                m.size = member.size
                m.mtime = int(target_mtime)
                m.mode = member.mode
                m.type = member.type
                m.linkname = member.linkname
                m.uid = 0
                m.gid = 0
                m.uname = ""
                m.gname = ""
                f = tf_in.extractfile(member) if member.isfile() else None
                tf_out.addfile(m, f)

    normalized_tar = tar_out_buf.getvalue()
    gz_out_buf = io.BytesIO()
    with gzip.GzipFile(filename="", mode="wb", fileobj=gz_out_buf, mtime=int(target_mtime)) as gz_out:
        gz_out.write(normalized_tar)

    final_bytes = gz_out_buf.getvalue()
    normalized_path = sdist_path.with_name(sdist_path.stem + "_normalized.tar.gz")
    normalized_path.write_bytes(final_bytes)
    return hashlib.sha256(final_bytes).hexdigest(), len(final_bytes), normalized_path


def prepare_fresh_build_environment(tmp_dir: Path, host_python: str) -> dict:
    """Create a separate fresh build virtual environment for each build phase.
    Installs pinned build toolchain and verifies interpreter isolation.
    """
    venv_dir = tmp_dir / "fresh_build_venv"
    rc, out, err = run_cmd([host_python, "-m", "venv", str(venv_dir)])
    if rc != 0:
        raise RuntimeError(f"Failed to create virtual environment in {venv_dir}: {err}\n{out}")

    if os.name == "nt":
        venv_python = venv_dir / "Scripts" / "python.exe"
    else:
        venv_python = venv_dir / "bin" / "python"

    if not venv_python.exists():
        raise RuntimeError(f"Virtual environment Python executable not found at {venv_python}")

    install_reqs = [f"{pkg}=={ver}" for pkg, ver in PINNED_TOOLS.items()]
    cmd_inst = [
        str(venv_python),
        "-m",
        "pip",
        "install",
        "--quiet",
        "--trusted-host",
        "pypi.org",
        "--trusted-host",
        "files.pythonhosted.org",
        "--trusted-host",
        "pypi.python.org",
    ] + install_reqs

    rc_inst, out_inst, err_inst = run_cmd(cmd_inst)
    if rc_inst != 0:
        raise RuntimeError(
            f"Failed to install pinned build tools into fresh environment {venv_python}: {err_inst}\n{out_inst}"
        )

    verify_code = (
        "import sys, json; "
        "print(json.dumps([sys.executable, sys.prefix, sys.base_prefix]))"
    )
    rc_chk, out_chk, err_chk = run_cmd([str(venv_python), "-c", verify_code])
    if rc_chk != 0:
        raise RuntimeError(f"Failed to verify fresh venv interpreter isolation: {err_chk}")

    interp_info = json.loads(out_chk)
    venv_executable, venv_prefix, venv_base_prefix = interp_info[0], interp_info[1], interp_info[2]
    if venv_prefix == venv_base_prefix:
        raise RuntimeError(f"Interpreter {venv_python} is not isolated (sys.prefix == sys.base_prefix)")

    rc_ver, out_ver, err_ver = run_cmd([str(venv_python), "-m", "pip", "list", "--format=json"])
    if rc_ver != 0:
        raise RuntimeError(f"Failed to list installed package versions in venv: {err_ver}")

    installed_list = json.loads(out_ver)
    actual_versions = {item["name"].lower(): item["version"] for item in installed_list}
    for pkg, exp_ver in PINNED_TOOLS.items():
        act_ver = actual_versions.get(pkg.lower())
        if act_ver != exp_ver:
            raise RuntimeError(
                f"Package {pkg} version mismatch in fresh venv: expected {exp_ver}, got {act_ver}"
            )

    return {
        "python_executable": venv_executable,
        "sys_prefix": venv_prefix,
        "sys_base_prefix": venv_base_prefix,
        "execution_mode": "fresh_isolated_venv",
        "verified_tools": {pkg: actual_versions[pkg.lower()] for pkg in PINNED_TOOLS},
    }


def resolve_source_ref(repo_root: Path, source_ref: str) -> tuple[str, int]:
    """Resolve a source ref (tag, branch, SHA) to a commit SHA and timestamp.

    Returns (commit_sha, commit_timestamp).
    """
    rc, resolved_sha, err = run_cmd(
        ["git", "rev-list", "-n", "1", source_ref],
        cwd=str(repo_root),
    )
    if rc != 0:
        raise ValueError(
            f"Could not resolve --source-ref '{source_ref}' to a commit: {err}"
        )

    rc, ts_str, err = run_cmd(
        ["git", "log", "-1", "--format=%ct", resolved_sha],
        cwd=str(repo_root),
    )
    if rc != 0:
        raise ValueError(
            f"Could not determine commit timestamp for {resolved_sha}: {err}"
        )

    try:
        commit_ts = int(ts_str.strip())
    except ValueError:
        raise ValueError(f"Invalid commit timestamp: '{ts_str}'")

    return resolved_sha, commit_ts


def extract_source_tree(repo_root: Path, commit_sha: str, dest_dir: Path) -> None:
    """Extract the exact source tree for a commit via git archive.

    This ensures the build uses the exact source at the requested revision,
    independent of the current working-tree state. The resulting tree excludes
    .git/, untracked files, and any local modifications.
    """
    # Use git archive to produce a tar stream, then extract it
    archive_cmd = ["git", "archive", "--format=tar", commit_sha]
    archive_proc = subprocess.Popen(
        archive_cmd,
        cwd=str(repo_root),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    stdout_data, stderr_data = archive_proc.communicate()
    if archive_proc.returncode != 0:
        raise RuntimeError(
            f"git archive failed for commit {commit_sha}: {stderr_data.decode()}"
        )

    dest_dir.mkdir(parents=True, exist_ok=True)
    tar_buf = io.BytesIO(stdout_data)
    with tarfile.open(fileobj=tar_buf, mode="r:") as tf:
        tf.extractall(path=str(dest_dir))

    # Validate that the extracted source contains pyproject.toml (sanity check)
    if not (dest_dir / "pyproject.toml").exists():
        raise RuntimeError(
            f"Extracted source tree for {commit_sha} does not contain pyproject.toml — "
            f"the commit may not correspond to a buildable source tree."
        )


def load_reference_artifacts(reference_dir: Path) -> dict:
    """Load reference artifacts from the given directory.

    Returns a dict with 'wheel' and 'sdist' sub-dicts containing
    filename, hash, and size.

    Raises RuntimeError if expected artifacts are missing.
    """
    ref_path = Path(reference_dir)
    if not ref_path.is_dir():
        raise RuntimeError(f"--reference-dir '{reference_dir}' is not a directory")

    wheels = list(ref_path.glob("*.whl"))
    sdists = list(ref_path.glob("*.tar.gz"))

    if not wheels:
        raise RuntimeError(
            f"No wheel (.whl) artifact found in --reference-dir '{reference_dir}'"
        )
    if not sdists:
        raise RuntimeError(
            f"No sdist (.tar.gz) artifact found in --reference-dir '{reference_dir}'"
        )

    wheel_path = wheels[0]
    sdist_path = sdists[0]

    return {
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


def compute_verdict(build_results: list, reference: dict | None) -> dict:
    """Compute the reproducibility verdict from build results and optional reference.

    Returns a dict with verdict fields.
    """
    whl_match = (
        build_results[0]["wheel"]["hash"] == build_results[1]["wheel"]["hash"]
        and build_results[0]["wheel"]["size"] == build_results[1]["wheel"]["size"]
    )
    raw_sdist_match = (
        build_results[0]["sdist"]["raw"]["hash"] == build_results[1]["sdist"]["raw"]["hash"]
        and build_results[0]["sdist"]["raw"]["size"] == build_results[1]["sdist"]["raw"]["size"]
    )
    normalized_sdist_match = (
        build_results[0]["sdist"]["normalized"]["hash"] == build_results[1]["sdist"]["normalized"]["hash"]
        and build_results[0]["sdist"]["normalized"]["size"] == build_results[1]["sdist"]["normalized"]["size"]
    )

    is_reproducible = whl_match and raw_sdist_match

    reference_parity = None
    reference_details = None
    if reference is not None:
        ref_whl_match = (
            build_results[0]["wheel"]["hash"] == reference["wheel"]["hash"]
            and build_results[0]["wheel"]["size"] == reference["wheel"]["size"]
        )
        ref_sdist_match = (
            build_results[0]["sdist"]["raw"]["hash"] == reference["sdist"]["hash"]
            and build_results[0]["sdist"]["raw"]["size"] == reference["sdist"]["size"]
        )
        reference_parity = ref_whl_match and ref_sdist_match

        if not reference_parity:
            is_reproducible = False

        reference_details = {
            "wheel_parity": ref_whl_match,
            "sdist_parity": ref_sdist_match,
            "reference_wheel": reference["wheel"],
            "reference_sdist": reference["sdist"],
        }

    outcome = "REPRODUCIBLE" if is_reproducible else "NON_REPRODUCIBLE"

    return {
        "wheel_reproducible": whl_match,
        "raw_sdist_reproducible": raw_sdist_match,
        "normalized_sdist_reproducible": normalized_sdist_match,
        "reference_parity": reference_parity,
        "reference_details": reference_details,
        "outcome": outcome,
    }


def parse_args(argv=None):
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(
        description="Verify reproducible builds of the CryptoFlex package.",
    )
    parser.add_argument(
        "--source-ref",
        default="HEAD",
        help=(
            "Git ref (tag, branch, or SHA) to build from. "
            "Defaults to HEAD. Example: --source-ref v0.5.3"
        ),
    )
    parser.add_argument(
        "--reference-dir",
        default=None,
        help=(
            "Directory containing reference artifacts (wheel and sdist) to compare "
            "against. If omitted, only self-consistency between two fresh builds is "
            "checked. The local dist/ directory is NEVER implicitly used."
        ),
    )
    return parser.parse_args(argv)


def main(argv=None):
    args = parse_args(argv)
    repo_root = Path(__file__).resolve().parents[1]
    host_python = sys.executable

    # --- Resolve source ref ---
    try:
        commit_sha, commit_ts = resolve_source_ref(repo_root, args.source_ref)
    except ValueError as e:
        print("UNABLE_TO_VERIFY")
        print(str(e))
        sys.exit(1)

    print(f"Source ref: {args.source_ref}")
    print(f"Resolved commit: {commit_sha}")
    print(f"Commit timestamp (SOURCE_DATE_EPOCH): {commit_ts}")

    # --- Load reference artifacts if requested ---
    reference = None
    if args.reference_dir is not None:
        try:
            reference = load_reference_artifacts(Path(args.reference_dir))
            print(f"Reference dir: {args.reference_dir}")
            print(f"  Wheel: {reference['wheel']['filename']}  SHA-256: {reference['wheel']['hash']}")
            print(f"  Sdist: {reference['sdist']['filename']}  SHA-256: {reference['sdist']['hash']}")
        except RuntimeError as e:
            print("UNABLE_TO_VERIFY")
            print(str(e))
            sys.exit(1)

    # --- Perform two independent builds ---
    build_results = []
    build_modes = []
    for i in range(2):
        tmp_dir = Path(tempfile.mkdtemp(prefix=f"cryptoflex_fresh_build_{i+1}_"))
        try:
            src_dir = tmp_dir / "crypto_flex"
            extract_source_tree(repo_root, commit_sha, src_dir)

            env_info = prepare_fresh_build_environment(tmp_dir, host_python)
            build_python = env_info["python_executable"]
            build_modes.append(env_info["execution_mode"])

            env = os.environ.copy()
            env["SOURCE_DATE_EPOCH"] = str(commit_ts)
            rc, out, err = run_cmd(
                [
                    build_python,
                    "-m",
                    "build",
                    "--sdist",
                    "--wheel",
                ],
                cwd=str(src_dir),
                env=env,
            )
            if rc != 0:
                raise RuntimeError(f"Build {i+1} failed: {err}\n{out}")

            dist_dir = src_dir / "dist"
            wheels = list(dist_dir.glob("*.whl"))
            sdists = list(dist_dir.glob("*.tar.gz"))

            if not wheels:
                raise RuntimeError(f"Build {i+1} produced no wheel artifact")
            if not sdists:
                raise RuntimeError(f"Build {i+1} produced no sdist artifact")

            wheel_path = wheels[0]
            sdist_path = sdists[0]

            wheel_hash = sha256_file(wheel_path)
            wheel_size = wheel_path.stat().st_size

            raw_sdist_hash = sha256_file(sdist_path)
            raw_sdist_size = sdist_path.stat().st_size

            normalized_hash, normalized_size, normalized_path = normalize_sdist_copy(sdist_path, commit_ts)

            build_results.append(
                {
                    "build_id": i + 1,
                    "environment": env_info["execution_mode"],
                    "python_executable": build_python,
                    "sys_prefix": env_info["sys_prefix"],
                    "sys_base_prefix": env_info["sys_base_prefix"],
                    "wheel": {
                        "filename": wheel_path.name,
                        "hash": wheel_hash,
                        "size": wheel_size,
                    },
                    "sdist": {
                        "raw": {
                            "filename": sdist_path.name,
                            "hash": raw_sdist_hash,
                            "size": raw_sdist_size,
                        },
                        "normalized": {
                            "filename": normalized_path.name,
                            "hash": normalized_hash,
                            "size": normalized_size,
                        },
                    },
                }
            )
        except Exception as e:
            print("UNABLE_TO_VERIFY")
            print(f"Error during build {i+1}: {e}")
            shutil.rmtree(tmp_dir, ignore_errors=True)
            sys.exit(1)
        finally:
            shutil.rmtree(tmp_dir, ignore_errors=True)

    # --- Compute verdict ---
    verdict = compute_verdict(build_results, reference)
    outcome = verdict["outcome"]
    print(outcome)

    if not verdict["wheel_reproducible"]:
        print(
            f"WHEEL MISMATCH: build1={build_results[0]['wheel']['hash']} "
            f"build2={build_results[1]['wheel']['hash']}"
        )
    if not verdict["raw_sdist_reproducible"]:
        print(
            f"SDIST MISMATCH: build1={build_results[0]['sdist']['raw']['hash']} "
            f"build2={build_results[1]['sdist']['raw']['hash']}"
        )
    if verdict["reference_parity"] is False:
        details = verdict["reference_details"]
        if not details["wheel_parity"]:
            print(
                f"REFERENCE WHEEL PARITY FAILED: "
                f"reference={details['reference_wheel']['hash']} "
                f"rebuilt={build_results[0]['wheel']['hash']}"
            )
        if not details["sdist_parity"]:
            print(
                f"REFERENCE SDIST PARITY FAILED: "
                f"reference={details['reference_sdist']['hash']} "
                f"rebuilt={build_results[0]['sdist']['raw']['hash']}"
            )

    summary = {
        "source_ref": args.source_ref,
        "resolved_commit_sha": commit_sha,
        "commit_timestamp": commit_ts,
        "pinned_toolchain": PINNED_TOOLS,
        "execution_modes": build_modes,
        "wheel_reproducible": verdict["wheel_reproducible"],
        "raw_sdist_reproducible": verdict["raw_sdist_reproducible"],
        "normalized_sdist_reproducible": verdict["normalized_sdist_reproducible"],
        "reference_parity": verdict["reference_parity"],
        "reference_details": verdict["reference_details"],
        "builds": build_results,
        "outcome": outcome,
    }
    print("\n---SUMMARY---")
    print(json.dumps(summary, indent=2))
    if outcome != "REPRODUCIBLE":
        sys.exit(1)

if __name__ == "__main__":
    main()
