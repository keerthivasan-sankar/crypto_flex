import os
import sys
import unittest
from unittest import mock
from pathlib import Path

# Import the helper function from the repository
from scripts.reproduce_release import ensure_windows_system_ca_bundle

class TestWindowsCAHelper(unittest.TestCase):
    @mock.patch('platform.system')
    def test_helper_noop_on_non_windows(self, mock_system):
        mock_system.return_value = "Linux"
        result = ensure_windows_system_ca_bundle()
        self.assertIsNone(result, "Helper should return None on non-Windows platforms")

    @unittest.skipUnless(sys.platform == 'win32', 'requires the Windows certificate store')
    @mock.patch('platform.system')
    def test_helper_creates_bundle_on_windows(self, mock_system):
        mock_system.return_value = "Windows"
        # Ensure environment is clean
        for var in ["SSL_CERT_FILE", "PIP_CERT", "REQUESTS_CA_BUNDLE"]:
            os.environ.pop(var, None)
        result = ensure_windows_system_ca_bundle()
        self.assertIsNotNone(result, "Helper should return a Path on Windows when successful")
        bundle_path = Path(result)
        self.assertTrue(bundle_path.exists(), "Bundle file should exist")
        # Verify env vars are set to the bundle path string
        for var in ["SSL_CERT_FILE", "PIP_CERT", "REQUESTS_CA_BUNDLE"]:
            self.assertIn(var, os.environ)
            self.assertEqual(os.environ[var], str(bundle_path))
        # Clean up the created bundle directory (temporary location under system temp)
        try:
            bundle_dir = bundle_path.parent
            if bundle_dir.exists():
                for child in bundle_dir.iterdir():
                    child.unlink()
                bundle_dir.rmdir()
        except Exception:
            pass

if __name__ == "__main__":
    unittest.main()
