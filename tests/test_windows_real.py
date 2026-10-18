import os
import platform
import subprocess
import sys
import ssl
import tempfile
from pathlib import Path

import pytest

# Import the helper from the repository
from scripts.reproduce_release import ensure_windows_system_ca_bundle


def _run_helper_and_print_temp_dir(ca_dir: Path | None = None) -> str:
    """Run ``ensure_windows_system_ca_bundle`` in a subprocess and return the printed directory.

    The helper script prints the *parent* directory of the generated bundle (or ``"None"``).
    When a caller‑supplied ``ca_dir`` is given we verify the bundle file exists before returning.
    When ``ca_dir`` is ``None`` the function intentionally does **not** check the bundle file –
    the atexit cleanup will delete the temporary directory as soon as the subprocess exits,
    and the parent process should observe the directory's removal.
    """
    script = (
        "import sys;\n"
        "from pathlib import Path;\n"
        "from scripts.reproduce_release import ensure_windows_system_ca_bundle;\n"
        "tmp = ensure_windows_system_ca_bundle(ca_dir=Path(sys.argv[1]) if sys.argv[1] != 'None' else None);\n"
        "print(tmp.parent if tmp else 'None')"
    )
    cmd = [sys.executable, "-c", script, str(ca_dir) if ca_dir else "None"]
    result = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        timeout=30,
        check=True,
    )
    stdout = result.stdout.strip()
    assert stdout != "", "Subprocess produced no output"
    if ca_dir is not None and stdout != "None":
        # When we supplied a directory, the bundle should exist there.
        bundle_path = Path(stdout) / "win_sys_ca_bundle.pem"
        assert bundle_path.is_file(), f"Bundle file not found at {bundle_path}"
    return stdout


@pytest.mark.skipif(platform.system() != "Windows", reason="Windows‑specific test, skip on other platforms")
def test_bundle_creation_tempdir(monkeypatch):
    """Ensure a temporary directory is created and cleaned up after interpreter exit.

    The helper runs in a separate Python process, which registers an ``atexit`` cleanup.
    After the subprocess finishes we confirm the temporary directory no longer exists.
    """
    temp_dir_path = _run_helper_and_print_temp_dir()
    assert temp_dir_path != "None"
    assert not Path(temp_dir_path).exists()


@pytest.mark.skipif(platform.system() != "Windows", reason="Windows‑specific test, skip on other platforms")
def test_bundle_creation_with_cadir(tmp_path, monkeypatch):
    """When a caller‑supplied directory is given, it should not be removed automatically.

    The helper creates the bundle inside ``tmp_path``; after the subprocess exits we verify
    that both the bundle file and the supplied directory remain.
    """
    temp_dir_path = _run_helper_and_print_temp_dir(tmp_path)
    assert temp_dir_path != "None"
    bundle_path = Path(temp_dir_path) / "win_sys_ca_bundle.pem"
    assert bundle_path.is_file()
    # The caller‑supplied directory must still exist.
    assert tmp_path.exists()


@pytest.mark.skipif(platform.system() != "Windows", reason="Windows‑specific test, skip on other platforms")
def test_https_request_success(monkeypatch):
    """Perform a real HTTPS request using the generated bundle and verify verification.

    The test creates the bundle via ``ensure_windows_system_ca_bundle`` (default temp dir),
    confirms the PEM file contains at least one syntactically valid X.509 certificate using
    the ``cryptography`` library, forces the ``requests`` library to use the bundle via the
    standard environment variables, and captures the ``ssl.SSLContext.load_verify_locations``
    call to ensure the bundle path is actually supplied to the TLS context.
    """
    # Ensure a clean environment for the variables.
    for var in ("SSL_CERT_FILE", "PIP_CERT", "REQUESTS_CA_BUNDLE"):
        monkeypatch.delenv(var, raising=False)

    # Create the bundle.
    bundle_path = ensure_windows_system_ca_bundle()
    assert bundle_path is not None and bundle_path.is_file()

    # Verify environment variables point to the bundle.
    for var in ("SSL_CERT_FILE", "PIP_CERT", "REQUESTS_CA_BUNDLE"):
        assert os.getenv(var) == str(bundle_path)

    # ----- Validate bundle PEM content and X.509 parsing -----
    pem_data = bundle_path.read_text(encoding="utf-8")
    blocks = [blk for blk in pem_data.split("-----END CERTIFICATE-----") if "-----BEGIN CERTIFICATE-----" in blk]
    assert blocks, "No PEM certificate blocks found in the bundle"
    import base64, re
    # Optional: use cryptography to parse each certificate.
    try:
        from cryptography import x509
        from cryptography.hazmat.backends import default_backend
    except Exception as e:
        pytest.fail(f"cryptography library unavailable: {e}")
    for blk in blocks:
        m = re.search(r"-----BEGIN CERTIFICATE-----\s*(.+?)\s*-----END CERTIFICATE-----", blk, re.DOTALL)
        if m:
            clean = "".join(m.group(1).split())
            try:
                der_bytes = base64.b64decode(clean, validate=True)
            except Exception as e:
                pytest.fail(f"Invalid base64 in PEM block: {e}")
            # Parse X.509 certificate; will raise if malformed.
            try:
                x509.load_der_x509_certificate(der_bytes, backend=default_backend())
            except Exception as e:
                pytest.fail(f"Malformed X.509 certificate: {e}")

    # ----- Capture SSLContext usage -----
    loaded_path = {}
    original_load = ssl.SSLContext.load_verify_locations

    def capture_load(self, cafile=None, *args, **kwargs):
        if cafile:
            loaded_path["cafile"] = cafile
        return original_load(self, cafile, *args, **kwargs)

    monkeypatch.setattr(ssl.SSLContext, "load_verify_locations", capture_load)

    # Perform a simple HTTPS GET request.
    try:
        import requests
    except ImportError:
        pytest.fail("requests library not installed")

    # Guard against explicit ``verify=False`` in user code.
    original_get = requests.get

    def guard_get(*args, **kwargs):
        if kwargs.get("verify") is False:
            raise AssertionError("TLS verification was disabled via verify=False")
        return original_get(*args, **kwargs)

    monkeypatch.setattr(requests, "get", guard_get)

    try:
        resp = requests.get("https://www.example.com", timeout=10)
        assert resp.status_code == 200
    except requests.exceptions.SSLError as e:
        pytest.fail(f"TLS verification failed: {e}")
    except requests.exceptions.RequestException as e:
        pytest.fail(f"Network request failed (not a TLS verification issue): {e}")

    # Ensure the SSLContext was instructed to load the generated bundle.
    assert loaded_path.get("cafile") == str(bundle_path), (
        "SSLContext was not instructed to load the generated CA bundle"
    )
    # No manual cleanup – atexit will delete the temporary dir when the process exits.
    # End of test_https_request_success
