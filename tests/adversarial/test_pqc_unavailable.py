import os
import pytest
from cryptoflex.sources import PQCSource, SourceUnavailableError

def test_pqc_source_unavailable_when_disabled(monkeypatch):
    monkeypatch.setenv("CRYPTOFLEX_DISABLE_PQC", "1")
    src = PQCSource()
    assert not src.is_available()
    with pytest.raises(SourceUnavailableError):
        src.generate_keypair()
