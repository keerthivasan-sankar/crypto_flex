"""verify_reproducibility.py

Utility to test reproducible builds of the CryptoFlex package.

It performs two independent builds from the *same* Git revision using separate
temporary source copies and separate fresh virtual build environments populated with
pinned build dependencies (pip==26.2.1, setuptools==84.0.0, wheel==0.48.0, build==1.6.0).

The script records raw artifact hashes for the wheel and the source distribution
before any normalization. It then optionally compares those builds against a
reference directory supplied by the caller.

The script reports one of four outcomes:
  * REPRODUCIBLE – raw wheel and raw sdist are identical across two builds (and match reference if provided).
  * NON_REPRODUCIBLE – artifact hashes differ.
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

    # Verify interpreter isolation
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


def extract_source(commit_sha: str, dest_dir: Path, repo_root: Path):
    """Extract the tracked files of ``commit_sha`` into ``dest_dir`` using ``git archive``.
    Guarantees that only committed files are present; untracked files are ignored.
    """
    # Run `git archive <sha>` and pipe to tar extraction
    proc = subprocess.run(
        ["git", "archive", commit_sha],
        cwd=str(repo_root),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if proc.returncode != 0:
        raise RuntimeError(f"git archive failed for {commit_sha}: {proc.stderr.decode().strip()}")
    archive_data = proc.stdout
    with tarfile.open(fileobj=io.BytesIO(archive_data)) as tf:
        tf.extractall(path=dest_dir)


def main():
    parser = argparse.ArgumentParser(description="Verify reproducible builds of CryptoFlex.")
    parser.add_argument("--source-ref", default="HEAD", help="Git reference (tag, branch, or commit) to verify. Defaults to HEAD.")
    parser.add_argument("--reference-dir", default=None, help="Path to a directory containing reference wheel and sdist artifacts.")
    args = parser.parse_args()

    repo_root = Path(__file__).resolve().parents[1]
    host_python = sys.executable

    # Resolve source reference to full commit SHA
    rc, resolved_sha, _ = run_cmd(["git", "rev-parse", f"{args.source_ref}^{{commit}}"], cwd=str(repo_root))
    if rc != 0:
        print("UNABLE_TO_VERIFY")
        print(f"Could not resolve source reference '{args.source_ref}'")
        sys.exit(1)
    resolved_sha = resolved_sha.strip()

    # Resolve commit timestamp
    rc, commit_ts_str, _ = run_cmd(["git", "log", "-1", "--format=%ct", resolved_sha], cwd=str(repo_root))
    if rc != 0:
        print("UNABLE_TO_VERIFY")
        print("Could not determine commit timestamp")
        sys.exit(1)
    try:
        commit_ts = int(commit_ts_str.strip())
    except ValueError:
        print("UNABLE_TO_VERIFY")
        print(f"Invalid commit timestamp: '{commit_ts_str}'")
        sys.exit(1)

    build_results = []
    build_modes = []
    for i in range(2):
        tmp_dir = Path(tempfile.mkdtemp(prefix=f"cryptoflex_fresh_build_{i+1}_"))
        try:
            src_dir = tmp_dir / "crypto_flex"
            src_dir.mkdir(parents=True, exist_ok=True)
            # Extract exact source tree for the resolved commit
            extract_source(resolved_sha, src_dir, repo_root)

            env_info = prepare_fresh_build_environment(tmp_dir, host_python)
            build_python = env_info["python_executable"]
            build_modes.append(env_info["execution_mode"])

            env = os.environ.copy()
            env["SOURCE_DATE_EPOCH"] = str(commit_ts)
            rc, out, err = run_cmd(
                [
                    str(build_python),
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

    # Reference directory handling
    reference_parity = None
    if args.reference_dir:
        ref_dir = Path(args.reference_dir)
        if not ref_dir.is_dir():
            print("UNABLE_TO_VERIFY")
            print(f"Reference directory {ref_dir} does not exist")
            sys.exit(1)
        ref_wheels = list(ref_dir.glob("*.whl"))
        ref_sdists = list(ref_dir.glob("*.tar.gz"))
        if not ref_wheels or not ref_sdists:
            print("UNABLE_TO_VERIFY")
            print("Reference directory missing required .whl or .tar.gz files")
            sys.exit(1)
        ref_wheel_hash = sha256_file(ref_wheels[0])
        ref_sdist_hash = sha256_file(ref_sdists[0])
        wheel_ref_match = (ref_wheel_hash == build_results[0]["wheel"]["hash"])
        sdist_ref_match = (ref_sdist_hash == build_results[0]["sdist"]["raw"]["hash"])
        reference_parity = wheel_ref_match and sdist_ref_match
        if not reference_parity:
            is_reproducible = False

    outcome = "REPRODUCIBLE" if is_reproducible else "NON_REPRODUCIBLE"
    print(outcome)

    summary = {
        "source_ref": args.source_ref,
        "resolved_commit_sha": resolved_sha,
        "commit_timestamp": commit_ts,
        "pinned_toolchain": PINNED_TOOLS,
        "execution_modes": build_modes,
        "wheel_reproducible": whl_match,
        "raw_sdist_reproducible": raw_sdist_match,
        "normalized_sdist_reproducible": normalized_sdist_match,
        "reference_dir": args.reference_dir,
        "reference_parity": reference_parity,
        "builds": build_results,
        "outcome": outcome,
    }
    print("\n---SUMMARY---")
    print(json.dumps(summary, indent=2))
    if not is_reproducible:
        sys.exit(1)


if __name__ == "__main__":
    main()
