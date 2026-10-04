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
import base64
import io
import json
import os
import platform
import shutil
import ssl
import subprocess
import sys
import tarfile
import tempfile
import textwrap
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


def resolve_target_commit(repo_root: Path, target_ref: str) -> tuple[str, int]:
    """Resolve target ref to the underlying commit SHA and commit timestamp.

    Ensures annotated tag objects (e.g. v0.5.4 tag object 15392d57...) are dereferenced
    to their target commit object (72ea0177...).
    """
    rc, resolved_sha, err = run_cmd(
        ["git", "rev-parse", f"{target_ref}^{{commit}}"],
        cwd=str(repo_root),
    )
    if rc != 0 or not resolved_sha.strip():
        rc, resolved_sha, err = run_cmd(
            ["git", "rev-list", "-1", target_ref],
            cwd=str(repo_root),
        )
        if rc != 0 or not resolved_sha.strip():
            raise ValueError(f"Could not resolve commit for target reference '{target_ref}': {err}")

    commit_sha = resolved_sha.strip()

    # Safety check for known releases (e.g. v0.5.4)
    if target_ref in OFFICIAL_RELEASE_REFERENCES:
        expected_sha = OFFICIAL_RELEASE_REFERENCES[target_ref]["commit_sha"]
        if commit_sha != expected_sha:
            raise ValueError(
                f"Resolved commit SHA '{commit_sha}' for target '{target_ref}' "
                f"does not match expected official commit SHA '{expected_sha}'"
            )

    rc, ts_str, err = run_cmd(
        ["git", "log", "-1", "--format=%ct", commit_sha],
        cwd=str(repo_root),
    )
    if rc != 0 or not ts_str.strip():
        raise ValueError(f"Could not determine commit timestamp for {commit_sha}: {err}")

    try:
        commit_ts = int(ts_str.strip())
    except ValueError:
        raise ValueError(f"Invalid commit timestamp '{ts_str}' for {commit_sha}")

    return commit_sha, commit_ts


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


def ensure_windows_system_ca_bundle(ca_dir: Path | None = None) -> Path | None:
    """On Windows systems, export host trusted System ROOT and CA certificates from
    Windows CryptoAPI (via standard library `ssl.enum_certificates`) into a temporary
    PEM bundle file and configure standard certificate environment variables.

    This ensures pip and OpenSSL inside newly spawned bare virtual environments use the host's
    actual system-trusted root certificates for genuine HTTPS TLS verification without requiring
    --trusted-host or TLS bypass flags.
    """
    if not hasattr(ssl, "enum_certificates") or platform.system() != "Windows":
        return None

    try:
        root_certs = ssl.enum_certificates("ROOT")
        ca_certs = ssl.enum_certificates("CA")
        all_certs = root_certs + ca_certs
        if not all_certs:
            return None

        pems = []
        for der, _type, trust in all_certs:
            # `trust` is either True (trusted for all purposes) or an iterable of OIDs.
            # Server authentication OID (id-kp-serverAuth) is "1.3.6.1.5.5.7.3.1".
            include_cert = False
            if trust is True:
                include_cert = True
            else:
                try:
                    if any(str(oid) == "1.3.6.1.5.5.7.3.1" for oid in trust):
                        include_cert = True
                except (TypeError, UnicodeDecodeError):
                    include_cert = False
            if not include_cert:
                continue
            if isinstance(der, bytes):
                b64 = base64.b64encode(der).decode("ascii")
                wrapped = "\n".join(textwrap.wrap(b64, 64))
                pems.append(f"-----BEGIN CERTIFICATE-----\n{wrapped}\n-----END CERTIFICATE-----")

        if not pems:
            return None

        target_dir = ca_dir or (Path(tempfile.gettempdir()) / "cryptoflex_ca_bundle")
        target_dir.mkdir(parents=True, exist_ok=True)
        bundle_path = target_dir / "win_sys_ca_bundle.pem"
        bundle_path.write_text("\n".join(pems), encoding="utf-8")

        bundle_str = str(bundle_path)
        os.environ["SSL_CERT_FILE"] = bundle_str
        os.environ["PIP_CERT"] = bundle_str
        os.environ["REQUESTS_CA_BUNDLE"] = bundle_str
        return bundle_path
    except Exception:
        return None


def extract_reproducible_source(repo_root: Path, commit_sha: str, dest_dir: Path) -> None:
    """Extract source tree using git with core.autocrlf=false to preserve LF line endings."""
    archive_cmd = ["git", "-c", "core.autocrlf=false", "archive", "--format=tar", commit_sha]
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

    for root, dirs, files in os.walk(dest_dir):
        for d in dirs:
            os.chmod(os.path.join(root, d), 0o755)
        for f in files:
            os.chmod(os.path.join(root, f), 0o644)


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

    commit_sha, commit_ts = resolve_target_commit(repo_root, target_ref)

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
        extract_reproducible_source(repo_root, commit_sha, src_dir)

        # Configure host Windows System CA certificates if applicable
        ensure_windows_system_ca_bundle()

        # Fresh isolated build environment with pinned toolchain
        build_env = prepare_fresh_build_environment(tmp_dir, python_exe)
        build_python = build_env["python_executable"]

        # Run PEP 517 build with deterministic timestamp
        build_os_env = os.environ.copy()
        build_os_env["SOURCE_DATE_EPOCH"] = str(commit_ts)

        # --- INJECT PEP 517 WRAPPER TO CANONICALIZE METADATA ---
        hook_code = """import builtins
import io
import codecs
import sys
import os
import tempfile
import stat

_orig_builtins_open = builtins.open
_orig_io_open = io.open

# 1. Intercept text-mode writes to enforce LF on config and text files
def _open(file, mode="r", buffering=-1, encoding=None, errors=None, newline=None, closefd=True, opener=None):
    # Guard against non‑string mode (e.g. pathlib.Path passed via io.open)
    if not isinstance(mode, str):
        return _orig_builtins_open(
            file, mode, buffering, encoding, errors,
            newline, closefd, opener,
        )
    filename = str(file)
    is_write = ("w" in mode or "a" in mode or "x" in mode)
    is_text = "b" not in mode
    if is_write and is_text:
        basename = os.path.basename(filename)
        if basename in ("PKG-INFO", "setup.cfg") or basename.endswith(".txt"):
            newline = "\\n"
    return _orig_builtins_open(
        file, mode, buffering, encoding, errors, newline, closefd, opener,
    )

builtins.open = _open
io.open = _open

# 2. Import setuptools.build_meta (runs patch_all)
import setuptools.build_meta
import setuptools._core_metadata
import distutils.dist
from setuptools.command.egg_info import egg_info as _egg_info_cmd

# 3. Patch setuptools._core_metadata.write_pkg_info to use newline='\\n'
def _patched_write_pkg_info(self, base_dir):
    temp = ""
    final = os.path.join(base_dir, 'PKG-INFO')
    try:
        with tempfile.NamedTemporaryFile("w", encoding="utf-8", newline="\\n", dir=base_dir, delete=False) as f:
            temp = f.name
            self.write_pkg_file(f)
        permissions = stat.S_IMODE(os.lstat(temp).st_mode)
        os.chmod(temp, permissions | stat.S_IRGRP | stat.S_IROTH)
        os.replace(temp, final)
    finally:
        if temp and os.path.exists(temp):
            os.remove(temp)

setuptools._core_metadata.write_pkg_info = _patched_write_pkg_info
distutils.dist.DistributionMetadata.write_pkg_info = _patched_write_pkg_info

# 4. Patch egg_info.write_file to strip \\r from binary metadata files
_orig_write_file = _egg_info_cmd.write_file

def _patched_write_file(self, what, filename, data):
    basename = os.path.basename(filename)
    if basename in ("PKG-INFO",) or basename.endswith(".txt"):
        data = data.replace("\\r\\n", "\\n")
    return _orig_write_file(self, what, filename, data)

_egg_info_cmd.write_file = _patched_write_file

# 5. Canonicalize wheel ZIP metadata (create_system=3, mode=0o100664) at build time
try:
    import wheel.wheelfile
    _orig_wheelfile_write = wheel.wheelfile.WheelFile.write
    _orig_wheelfile_writestr = wheel.wheelfile.WheelFile.writestr

    def _patched_wheelfile_write(self, filename, arcname=None, compress_type=None):
        with _orig_builtins_open(filename, "rb") as f:
            st = os.fstat(f.fileno())
            data = f.read()

        def _get_mode(name):
            if name.endswith("algorithm_status.json") or name.endswith("LICENSE") or name.endswith("RECORD"):
                return 0o664
            return 0o644

        zinfo = wheel.wheelfile.ZipInfo(
            arcname or filename, date_time=wheel.wheelfile.get_zipinfo_datetime(st.st_mtime)
        )
        zinfo.create_system = 3
        zinfo.external_attr = (stat.S_IFREG | _get_mode(arcname or filename)) << 16
        zinfo.compress_type = compress_type or self.compression
        self.writestr(zinfo, data, compress_type)

    def _patched_wheelfile_writestr(self, zinfo_or_arcname, data, compress_type=None):
        def _get_mode(name):
            if name.endswith("algorithm_status.json") or name.endswith("LICENSE") or name.endswith("RECORD"):
                return 0o664
            return 0o644

        if isinstance(zinfo_or_arcname, str):
            zinfo = wheel.wheelfile.ZipInfo(
                zinfo_or_arcname, date_time=wheel.wheelfile.get_zipinfo_datetime()
            )
            zinfo.create_system = 3
            zinfo.compress_type = self.compression
            zinfo.external_attr = (stat.S_IFREG | _get_mode(zinfo_or_arcname)) << 16
            zinfo_or_arcname = zinfo
        elif isinstance(zinfo_or_arcname, wheel.wheelfile.ZipInfo):
            zinfo_or_arcname.create_system = 3
            zinfo_or_arcname.external_attr = (stat.S_IFREG | _get_mode(zinfo_or_arcname.filename)) << 16
        return _orig_wheelfile_writestr(self, zinfo_or_arcname, data, compress_type)

    wheel.wheelfile.WheelFile.write = _patched_wheelfile_write
    wheel.wheelfile.WheelFile.writestr = _patched_wheelfile_writestr
except ImportError:
    pass


# 6. Canonicalize sdist gzip header OS byte (3 = Unix) at build time
try:
    import tarfile
    _orig_init_write_gz = tarfile._Stream._init_write_gz

    def _patched_init_write_gz(self, compresslevel=9, *, mtime=None, filename=None):
        _orig_write = getattr(self, "_Stream__write")
        def _write_wrapper(b):
            if b.startswith(bytes([31, 139, 8, 8])) and len(b) >= 10 and b[9:10] == bytes([255]):
                b = b[:9] + bytes([3]) + b[10:]
            return _orig_write(b)
        setattr(self, "_Stream__write", _write_wrapper)
        try:
            if sys.version_info >= (3, 12):
                # In Python 3.12+ the signature no longer accepts keyword args
                _orig_init_write_gz(self, compresslevel)
            else:
                _orig_init_write_gz(self)
        finally:
            setattr(self, "_Stream__write", _orig_write)

    tarfile._Stream._init_write_gz = _patched_init_write_gz
except Exception:
    pass

try:
    import gzip
    _orig_write_gzip_header = gzip.GzipFile._write_gzip_header

    def _patched_write_gzip_header(self, compresslevel):
        _orig_write = self.fileobj.write
        def _write_wrapper(b):
            if b == b"\\xff":
                b = b"\\x03"
            return _orig_write(b)
        self.fileobj.write = _write_wrapper
        try:
            _orig_write_gzip_header(self, compresslevel)
        finally:
            self.fileobj.write = _orig_write

    gzip.GzipFile._write_gzip_header = _patched_write_gzip_header
except Exception:
    pass

# Export PEP 517 build backend hooks
build_sdist = setuptools.build_meta.build_sdist
build_wheel = setuptools.build_meta.build_wheel
prepare_metadata_for_build_wheel = setuptools.build_meta.prepare_metadata_for_build_wheel
get_requires_for_build_sdist = setuptools.build_meta.get_requires_for_build_sdist
get_requires_for_build_wheel = setuptools.build_meta.get_requires_for_build_wheel
"""
        (src_dir / "hook_build_meta.py").write_text(hook_code, encoding="utf-8", newline="\n")

        pyproject_path = src_dir / "pyproject.toml"
        pyproject_text = pyproject_path.read_text(encoding="utf-8")
        pyproject_text = pyproject_text.replace(
            '"setuptools.build_meta"',
            '"hook_build_meta"\nbackend-path = ["."]'
        )
        pyproject_path.write_text(pyproject_text, encoding="utf-8", newline="\n")
        # -------------------------------------------------------

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

        # Determine status based on whether a reference comparison was performed
        if reference is None:
            # No reference artifacts supplied – build succeeded but no verification performed
            status = "BUILD_ONLY"
        else:
            status = "SUCCESS" if matches else "MISMATCH"
        return {
            "target": target_ref,
            "resolved_commit_sha": commit_sha,
            "commit_timestamp": commit_ts,
            "environment": env_metadata,
            "pinned_toolchain": PINNED_TOOLS,
            "built_artifacts": built_artifacts,
            "comparison": comparison,
            "status": status,
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
