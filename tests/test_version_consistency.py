import importlib.metadata
import cryptoflex

def test_runtime_version_matches_metadata():
    """Ensure runtime __version__ matches the distribution metadata version.

    The authoritative version is defined in pyproject.toml and emitted as
    ``importlib.metadata.version('cryptoflex')``.  The package's ``__version__``
    attribute should be kept in sync.
    """
    dist_version = importlib.metadata.version('cryptoflex')
    assert cryptoflex.__version__ == dist_version, (
        f"Runtime version {cryptoflex.__version__} does not match package metadata {dist_version}"
    )
