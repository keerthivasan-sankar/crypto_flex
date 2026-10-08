import base64
import pytest
from scripts import reproduce_release
import ssl

@pytest.fixture(autouse=True)
def mock_windows_platform(monkeypatch):
    """Force reproduce_release to think it's running on Windows."""
    monkeypatch.setattr(reproduce_release.platform, "system", lambda: "Windows")


@pytest.fixture(autouse=True)
def ensure_enum_certificates(monkeypatch):
    """Provide a no‑op ssl.enum_certificates on platforms where it is missing."""
    if not hasattr(reproduce_release.ssl, "enum_certificates"):
        monkeypatch.setattr(reproduce_release.ssl, "enum_certificates", lambda store: [], raising=False)

@pytest.fixture(autouse=True)
def clear_cert_env(monkeypatch):
    """Ensure SSL_CERT_FILE, PIP_CERT, REQUESTS_CA_BUNDLE are cleared before each test and restored after."""
    for var in ["SSL_CERT_FILE", "PIP_CERT", "REQUESTS_CA_BUNDLE"]:
        monkeypatch.delenv(var, raising=False)

FAKE_DER = b"fake-der-bytes"

def _mk_cert(trust):
    """Return a tuple compatible with ssl.enum_certificates output.
    `trust` can be:
        * True – trusted for all purposes
        * iterable of OID strings – specific EKU OIDs
    """
    return (FAKE_DER, "ROOT", trust)

def test_server_auth_included(monkeypatch, tmp_path):
    server_oid = "1.3.6.1.5.5.7.3.1"  # id‑kp‑serverAuth
    monkeypatch.setattr(reproduce_release.ssl, "enum_certificates", lambda store: [_mk_cert([server_oid])])
    bundle_path = reproduce_release.ensure_windows_system_ca_bundle(ca_dir=tmp_path)
    assert bundle_path is not None
    content = bundle_path.read_text()
    assert "-----BEGIN CERTIFICATE-----" in content
    b64 = base64.b64encode(FAKE_DER).decode("ascii")
    assert b64 in content

def test_email_protection_excluded(monkeypatch, tmp_path):
    email_oid = "1.3.6.1.5.5.7.3.4"  # id‑kp‑emailProtection
    monkeypatch.setattr(reproduce_release.ssl, "enum_certificates", lambda store: [_mk_cert([email_oid])])
    bundle_path = reproduce_release.ensure_windows_system_ca_bundle(ca_dir=tmp_path)
    # No server‑auth certificates, bundle should be None
    assert bundle_path is None

def test_all_purpose_trust_included(monkeypatch, tmp_path):
    monkeypatch.setattr(reproduce_release.ssl, "enum_certificates", lambda store: [_mk_cert(True)])
    bundle_path = reproduce_release.ensure_windows_system_ca_bundle(ca_dir=tmp_path)
    assert bundle_path is not None
    content = bundle_path.read_text()
    assert "-----BEGIN CERTIFICATE-----" in content
    b64 = base64.b64encode(FAKE_DER).decode("ascii")
    assert b64 in content
