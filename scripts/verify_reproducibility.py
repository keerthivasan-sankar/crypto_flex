"""verify_reproducibility.py

Utility to test reproducible builds of the CryptoFlex package.

It performs two independent builds from the *same* Git revision using separate
temporary source copies and separate fresh virtual build environments populated with
pinned build dependencies (pip==26.2.1, setuptools==84.0.0, wheel==0.48.0, build==1.6.0).

The script records raw artifact hashes for the wheel and the source distribution
before any normalization. It then optionally normalizes the sdist for reproducibility
reporting.

The script reports one of four outcomes:
  * REPRODUCIBLE – raw wheel and raw sdist are identical across two builds.
  * NORMALIZED_REPRODUCIBLE – raw wheel matches and normalized sdist matches, but raw sdist differs.
  * NON_REPRODUCIBLE – artifact hashes differ.
  * UNABLE_TO_VERIFY – the experiment could not be performed (e.g. build failure).
"""

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


def main():
    repo_root = Path(__file__).resolve().parents[1]
    host_python = sys.executable

    rc, commit_sha, _ = run_cmd(["git", "rev-parse", "HEAD"], cwd=str(repo_root))
    if rc != 0:
        print("UNABLE_TO_VERIFY")
        print("Could not determine current commit SHA")
        sys.exit(1)

    rc, commit_ts_str, _ = run_cmd(["git", "log", "-1", "--format=%ct", commit_sha], cwd=str(repo_root))
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
            shutil.copytree(
                repo_root,
                src_dir,
                dirs_exist_ok=True,
                ignore=shutil.ignore_patterns(
                    ".git",
                    "__pycache__",
                    "dist",
                    "build",
                    "*.egg-info",
                    "scripts",
                    ".pytest_cache",
                    ".hypothesis",
                ),
            )

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

    # Ensure release build parity: if dist/ exists, its artifacts MUST match the verified builds
    release_dist = repo_root / "dist"
    if release_dist.exists() and is_reproducible:
        release_wheels = list(release_dist.glob("*.whl"))
        release_sdists = list(release_dist.glob("*.tar.gz"))
        if release_wheels and release_sdists:
            rel_whl_hash = sha256_file(release_wheels[0])
            rel_sdist_hash = sha256_file(release_sdists[0])
            if rel_whl_hash != build_results[0]["wheel"]["hash"]:
                print(f"RELEASE PARITY FAILED: Release wheel hash {rel_whl_hash} does not match verified hash {build_results[0]['wheel']['hash']}")
                is_reproducible = False
            if rel_sdist_hash != build_results[0]["sdist"]["raw"]["hash"]:
                print(f"RELEASE PARITY FAILED: Release sdist hash {rel_sdist_hash} does not match verified hash {build_results[0]['sdist']['raw']['hash']}")
                is_reproducible = False

    outcome = "REPRODUCIBLE" if is_reproducible else "NON_REPRODUCIBLE"
    print(outcome)

    summary = {
        "commit_sha": commit_sha,
        "commit_timestamp": commit_ts,
        "pinned_toolchain": PINNED_TOOLS,
        "execution_modes": build_modes,
        "wheel_reproducible": whl_match,
        "raw_sdist_reproducible": raw_sdist_match,
        "normalized_sdist_reproducible": normalized_sdist_match,
        "builds": build_results,
        "outcome": outcome,
    }
    print("\n---SUMMARY---")
    print(json.dumps(summary, indent=2))
    if not is_reproducible:
        sys.exit(1)

if __name__ == "__main__":
    main()
