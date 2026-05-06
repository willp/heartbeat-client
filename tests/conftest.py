import pytest
from unittest.mock import patch


@pytest.fixture
def tmp_config_dir(tmp_path, monkeypatch):
    """Temporary config directory for testing."""
    config_dir = tmp_path / "hbclient"
    config_dir.mkdir(mode=0o700)
    monkeypatch.setattr("os.path.expanduser", lambda x: str(config_dir) if x == "~/.config/hbclient" else x)
    yield config_dir
    # Cleanup handled by tmp_path


@pytest.fixture
def sample_keys():
    """Sample key data for testing."""
    import time
    return {
        "access_token": "test_token_abc123",
        "aes_secret": "dGVzdF9zZWNyZXRfMTIzNDU2Nzg5MDEyMzQ1Njc=",
        "key_id": 42,
        "expires_at": int(time.time()) + 86400 * 30,
        "last_rotated_at": int(time.time()),
    }


@pytest.fixture
def mock_urlopen():
    """Mock urllib.request.urlopen."""
    with patch("urllib.request.urlopen") as mock:
        yield mock


@pytest.fixture
def mock_getfqdn():
    """Mock socket.getfqdn."""
    with patch("socket.getfqdn", return_value="testhost.example.com"):
        yield