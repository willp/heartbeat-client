"""Tests for HbConfig dataclass."""
from nuclei_heartbeat_client.hbclient import HbConfig


class TestHbConfigDefaults:
    """Test default values."""

    def test_default_server(self):
        config = HbConfig()
        assert config.server == "hb"

    def test_default_serverport(self):
        config = HbConfig()
        assert config.serverport == 8333

    def test_default_debug(self):
        config = HbConfig()
        assert config.debug is False

    def test_default_minimum_interval(self):
        config = HbConfig()
        assert config.MINIMUM_INTERVAL_SEC == 30

    def test_default_dns_refresh(self):
        config = HbConfig()
        assert config.DNS_REFRESH_SEC == 4 * 60 * 60  # 4 hours

    def test_default_alert_multipliers(self):
        config = HbConfig()
        assert config.ALERT_INTERVAL_MULTIPLIER_LOW == 2.25
        assert config.ALERT_INTERVAL_MULTIPLIER_HIGH == 1.25

    def test_default_dupe_send_delay(self):
        config = HbConfig()
        assert config.DUPE_SEND_DELAY_SEC is None


class TestHbConfigOverrides:
    """Test configuration overrides."""

    def test_override_server(self):
        config = HbConfig(server="hb2.example.com")
        assert config.server == "hb2.example.com"

    def test_override_serverport(self):
        config = HbConfig(serverport=9000)
        assert config.serverport == 9000

    def test_override_debug(self):
        config = HbConfig(debug=True)
        assert config.debug is True

    def test_override_dupe_send_delay_int(self):
        config = HbConfig(DUPE_SEND_DELAY_SEC=2)
        assert config.DUPE_SEND_DELAY_SEC == 2

    def test_override_dupe_send_delay_float(self):
        config = HbConfig(DUPE_SEND_DELAY_SEC=1.5)
        assert config.DUPE_SEND_DELAY_SEC == 1.5

    def test_override_dupe_send_delay_none(self):
        config = HbConfig(DUPE_SEND_DELAY_SEC=None)
        assert config.DUPE_SEND_DELAY_SEC is None