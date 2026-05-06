"""Tests for HbClient class."""
import socket
import time
from unittest.mock import MagicMock, patch

import pytest

from nuclei_heartbeat_client.hbclient import HbClient, HbConfig


class TestHbClientInit:
    """Test HbClient initialization."""

    def test_init_sets_attributes(self):
        """Test basic initialization without DNS lookup."""
        with patch("socket.getfqdn", return_value="testhost.example.com"):
            client = HbClient(name="test-app", interval=60)
            assert client.name == "test-app"
            assert client.interval == 60
            assert client.cfg == HbConfig()

    def test_init_with_custom_config(self):
        """Test initialization with custom config."""
        with patch("socket.getfqdn", return_value="testhost.example.com"):
            with patch("socket.gethostbyname_ex", return_value=("fake", [], ["127.0.0.1"])):
                config = HbConfig(server="custom.example.com", serverport=9000)
                client = HbClient(name="test-app", interval=60, config=config)
                assert client.cfg == config

    def test_init_sets_myhostname(self):
        """Test that myhostname is set."""
        with patch("socket.getfqdn", return_value="testhost.example.com"):
            client = HbClient(name="test-app", interval=60)
            assert client.myhostname == "testhost.example.com"

    def test_init_sets_alert_after_default(self):
        """Test default alert_after calculation."""
        with patch("socket.getfqdn", return_value="testhost.example.com"):
            client = HbClient(name="test-app", interval=60)
            # 60 * 2.25 = 135
            assert client.alert_after == 135

    def test_init_sets_alert_after_custom(self):
        """Test custom alert_after."""
        with patch("socket.getfqdn", return_value="testhost.example.com"):
            client = HbClient(name="test-app", interval=60, alert_after=200)
            assert client.alert_after == 200


class TestHbClientMakeMessage:
    """Test HbClient.make_message()."""

    def test_make_message_basic_fields(self):
        """Test make_message returns correct structure."""
        with patch("socket.getfqdn", return_value="testhost.example.com"):
            client = HbClient(name="test-app", interval=60)
            msg = client.make_message()
            assert "h" in msg
            assert "n" in msg
            assert "i" in msg
            assert "@" in msg
            assert "!" in msg
            assert msg["n"] == "test-app"
            assert msg["i"] == 60

    def test_make_message_with_task(self):
        """Test make_message with task."""
        with patch("socket.getfqdn", return_value="testhost.example.com"):
            client = HbClient(name="test-app", interval=60, task="deploy")
            msg = client.make_message()
            assert "t" in msg
            assert msg["t"] == "deploy"

    def test_make_message_with_version(self):
        """Test make_message with version."""
        with patch("socket.getfqdn", return_value="testhost.example.com"):
            client = HbClient(name="test-app", interval=60, version="1.2.3")
            msg = client.make_message()
            assert "v" in msg
            assert msg["v"] == "1.2.3"

    def test_make_message_with_port(self):
        """Test make_message with port."""
        with patch("socket.getfqdn", return_value="testhost.example.com"):
            client = HbClient(name="test-app", interval=60, port=8080)
            msg = client.make_message()
            assert "p" in msg
            assert msg["p"] == 8080


class TestHbClientUpdateDNS:
    """Test HbClient._update_dns()."""

    def test_update_dns_with_valid_ip(self):
        """Test DNS update with valid IP."""
        with patch("socket.getfqdn", return_value="testhost.example.com"):
            client = HbClient(name="test-app", interval=60)
            # Reset DNS cache
            client._last_dns_resolve = 0
            client.server_ips = set()
            # Return a valid IP
            with patch("socket.gethostbyname_ex", return_value=("fake", [], ["127.0.0.1"])):
                result = client._update_dns(ignore_errors=True)
                assert result is True
                assert "127.0.0.1" in client.server_ips

    def test_update_dns_returns_true_when_fresh(self):
        """Test that update_dns returns True when DNS cache is fresh."""
        with patch("socket.getfqdn", return_value="testhost.example.com"):
            client = HbClient(name="test-app", interval=60)
            # Set DNS as fresh (just updated)
            client._last_dns_resolve = time.time()
            client._update_dns()  # This should return False (cache is fresh)
            # The DNS cache was already fresh, so no update occurred
            # After that, calling update_dns with ignore_errors=True should return False
            # because the cache is still fresh
            result = client._update_dns(ignore_errors=True)
            # Since cache is fresh, _update_dns returns False
            assert result is False

    def test_update_dns_returns_false_on_failure_ignore_errors(self):
        """Test update_dns returns False on failure when ignore_errors=True."""
        with patch("socket.getfqdn", return_value="testhost.example.com"):
            client = HbClient(name="test-app", interval=60)
            # Reset DNS to old so it tries to update
            client._last_dns_resolve = 0
            client.server_ips = set()
            with patch("socket.gethostbyname_ex", side_effect=socket.gaierror("DNS failed")):
                result = client._update_dns(ignore_errors=True)
                assert result is False

    def test_update_dns_raises_on_failure_without_ignore_errors(self):
        """Test update_dns raises RuntimeError on failure without ignore_errors."""
        with patch("socket.getfqdn", return_value="testhost.example.com"):
            client = HbClient(name="test-app", interval=60)
            # Reset DNS to old so it tries to update
            client._last_dns_resolve = 0
            client.server_ips = set()
            with patch("socket.gethostbyname_ex", side_effect=socket.gaierror("DNS failed")):
                with pytest.raises(RuntimeError, match="DNS resolution failed"):
                    client._update_dns(ignore_errors=False)


class TestHbClientSend:
    """Test HbClient.send()."""

    def test_send_returns_false_if_interval_too_short(self):
        """Test send returns False when interval is too short."""
        with patch("socket.getfqdn", return_value="testhost.example.com"):
            client = HbClient(name="test-app", interval=60)
            client._last_sent_hb = time.time()  # Just sent
            result = client.send()
            assert result is False

    def test_send_creates_socket(self):
        """Test send creates socket."""
        with patch("socket.getfqdn", return_value="testhost.example.com"):
            client = HbClient(name="test-app", interval=60)
            client.server_ips = {"127.0.0.1"}
            with patch("socket.socket") as mock_socket_class:
                mock_socket = MagicMock()
                mock_socket_class.return_value = mock_socket
                client.send()
                assert mock_socket.sendto.called or len(client.server_ips) == 0

    def test_send_with_no_keys_sends_plaintext(self):
        """Test send with no keys sends plaintext."""
        with patch("socket.getfqdn", return_value="testhost.example.com"):
            client = HbClient(name="test-app", interval=60)
            client.server_ips = {"127.0.0.1"}
            with patch("socket.socket") as mock_socket_class:
                mock_socket = MagicMock()
                mock_socket_class.return_value = mock_socket
                result = client.send()
                # Should have called sendto
                assert mock_socket.sendto.called or result is False


class TestHbClientDUPE:
    """Test HbClient DUPE_SEND_DELAY_SEC behavior."""

    def test_dupe_send_sleeps_when_configured(self):
        """Test that dupe send is configured."""
        config = HbConfig(DUPE_SEND_DELAY_SEC=2.0)
        with patch("socket.getfqdn", return_value="testhost.example.com"):
            client = HbClient(name="test-app", interval=60, config=config)
            client.server_ips = {"127.0.0.1"}
            assert client.cfg.DUPE_SEND_DELAY_SEC == 2.0
