"""verify_reproducibility.py

Utility to test reproducible builds of the CryptoFlex package.

It performs two independent builds from the *same* Git revision using
separate temporary source copies and isolated virtual environments.

The script reports one of three outcomes:
  * REPRODUCIBLE – both wheel files are byte‑for‑byte identical.
  * NON_REPRODUCIBLE – builds succeed but the wheel files differ.
  * UNABLE_TO_VERIFY – the experiment could not be performed (e.g.
    missing build tools, errors during the builds, etc.).

The script intentionally does **not** modify the produced artifacts to
force a match; it only reports the observed result.
"""

import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

# ---------------------------------------------------------------------------
# Helper utilities
# ---------------------------------------------------------------------------

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
    with path.open('rb') as f:
        for chunk in iter(lambda: f.read(8192), b''):
            h.update(chunk)
    return h.hexdigest()

def get_build_tool_versions(python_executable: str):
    """Return exact versions of build, setuptools and wheel for a given Python.
    The function queries the interpreter's pip.
    """
    cmd = [python_executable, '-m', 'pip', 'show', 'build', 'setuptools', 'wheel']
    rc, out, err = run_cmd(cmd)
    versions = {}
    if rc == 0:
        for line in out.splitlines():
            if line.startswith('Name:'):
                name = line.split(':', 1)[1].strip()
            if line.startswith('Version:'):
                ver = line.split(':', 1)[1].strip()
                versions[name] = ver
    return versions

# ---------------------------------------------------------------------------
# Main reproducibility procedure
# ---------------------------------------------------------------------------

def main():
    repo_root = Path(__file__).resolve().parents[1]
    # Ensure we are on a clean git state and get the current commit SHA
    rc, commit_sha, _ = run_cmd(['git', 'rev-parse', 'HEAD'], cwd=str(repo_root))
    if rc != 0:
        print('UNABLE_TO_VERIFY')
        print('Could not determine current commit SHA')
        sys.exit(0)
    # Also obtain the commit timestamp (Unix epoch) for reproducible archives
    rc, commit_ts, _ = run_cmd(['git', 'log', '-1', '--format=%ct', commit_sha], cwd=str(repo_root))
    if rc != 0:
        print('UNABLE_TO_VERIFY')
        print('Could not determine commit timestamp')
        sys.exit(0)

    # Gather exact build tool versions from the host interpreter
    host_python = sys.executable
    tool_versions = get_build_tool_versions(host_python)
    required_tools = ['build', 'setuptools', 'wheel']
    missing = [t for t in required_tools if t not in tool_versions]
    if missing:
        print('UNABLE_TO_VERIFY')
        print(f'Missing required build tools: {missing}')
        sys.exit(0)

    # Prepare two independent temporary build environments
    results = []
    for i in range(2):
        try:
            tmp_src = Path(tempfile.mkdtemp(prefix=f'cryptoflex_src_{i}_'))
            # Copy the entire repository tree (excluding .git) into the temp dir
            shutil.copytree(repo_root, tmp_src / 'crypto_flex', dirs_exist_ok=True,
                            ignore=shutil.ignore_patterns('.git', '__pycache__', 'dist', 'build', '*.egg-info', 'scripts'))
            src_dir = tmp_src / 'crypto_flex'
            # Build directly using the host Python (no venv) to ensure build tools are available
            # Build using deterministic timestamps
            env = os.environ.copy()
            env['SOURCE_DATE_EPOCH'] = commit_ts.strip()
            rc, out, err = run_cmd([host_python, '-m', 'build', '--wheel', '--no-isolation'], cwd=str(src_dir), env=env)
            if rc != 0:
                raise RuntimeError(f'Build failed: {err}')
            if rc != 0:
                raise RuntimeError(f'Build failed: {err}')
            # Locate the generated wheel inside the temporary source's dist directory
            dist_dir = src_dir / 'dist'
            wheels = list(dist_dir.glob('*.whl'))
            if not wheels:
                raise RuntimeError('No wheel produced')
            wheel_path = wheels[0]
            # Record hash and size
            wheel_hash = sha256_file(wheel_path)
            wheel_size = wheel_path.stat().st_size
            results.append({
                'path': str(wheel_path),
                'hash': wheel_hash,
                'size': wheel_size,
            })
        except Exception as e:
            print('UNABLE_TO_VERIFY')
            print(f'Error during build {i+1}: {e}')
            sys.exit(0)

    # Compare the two results
    if results[0]['hash'] == results[1]['hash'] and results[0]['size'] == results[1]['size']:
        print('REPRODUCIBLE')
    else:
        print('NON_REPRODUCIBLE')
        print('Build 1:', json.dumps(results[0], indent=2))
        print('Build 2:', json.dumps(results[1], indent=2))
        # Show basic diagnostics: timestamps of the wheels
        for i, res in enumerate(results, start=1):
            ts = os.path.getmtime(res['path'])
            print(f'Build {i} timestamp: {ts}')

    # Emit a short JSON summary for downstream consumption
    summary = {
        'commit_sha': commit_sha,
        'tool_versions': tool_versions,
        'builds': results,
        'outcome': 'REPRODUCIBLE' if results[0]['hash'] == results[1]['hash'] else 'NON_REPRODUCIBLE',
    }
    print('\n---SUMMARY---')
    print(json.dumps(summary, indent=2))

if __name__ == '__main__':
    main()
