"""Tests for parse_time_duration function."""
import pytest

from hb_client.hbclient import parse_time_duration


class TestParseTimeDurationValid:
    """Test valid duration parsing."""

    def test_naked_number_seconds(self):
        assert parse_time_duration("300") == 300
        assert parse_time_duration("60") == 60

    def test_seconds_suffix(self):
        assert parse_time_duration("1s") == 1
        assert parse_time_duration("60s") == 60

    def test_minutes_suffix(self):
        assert parse_time_duration("1m") == 60
        assert parse_time_duration("5m") == 300
        assert parse_time_duration("30m") == 1800

    def test_hours_suffix(self):
        assert parse_time_duration("1h") == 3600
        assert parse_time_duration("2h") == 7200
        assert parse_time_duration("1.5h") == 5400

    def test_days_suffix(self):
        assert parse_time_duration("1d") == 86400
        assert parse_time_duration("2d") == 172800

    def test_weeks_suffix(self):
        assert parse_time_duration("1w") == 604800
        assert parse_time_duration("2w") == 1209600

    def test_months_suffix(self):
        assert parse_time_duration("1M") == 2592000
        assert parse_time_duration("2M") == 5184000

    def test_years_suffix(self):
        assert parse_time_duration("1y") == 31536000
        assert parse_time_duration("2y") == 63072000

    def test_decimal_values(self):
        assert parse_time_duration("1.5h") == 5400
        assert parse_time_duration("2.5d") == 216000
        assert parse_time_duration("0.5m") == 30

    def test_whitespace_handling(self):
        assert parse_time_duration("  5m  ") == 300
        assert parse_time_duration("\t1h\t") == 3600


class TestParseTimeDurationInvalid:
    """Test invalid duration parsing."""

    def test_empty_string(self):
        with pytest.raises(ValueError, match="non-empty string"):
            parse_time_duration("")

    def test_invalid_suffix(self):
        with pytest.raises(ValueError, match="Invalid duration"):
            parse_time_duration("1z")

    def test_invalid_format(self):
        with pytest.raises(ValueError, match="Invalid duration"):
            parse_time_duration("abc")

    def test_no_number(self):
        with pytest.raises(ValueError, match="Invalid duration"):
            parse_time_duration("abc")

    def test_negative_value(self):
        """Parsing "-1h" raises ValueError for negative durations."""
        with pytest.raises(ValueError):
            parse_time_duration("-1h")

    def test_zero_seconds(self):
        """"0" without a suffix is parsed as 0 seconds, which raises."""
        with pytest.raises(ValueError, match="greater than 0"):
            parse_time_duration("0")

    def test_zero_minutes(self):
        """'0m' is valid (zero minutes = zero seconds, raises ValueError)."""
        with pytest.raises(ValueError, match="greater than 0"):
            parse_time_duration("0m")

    def test_non_string_input(self):
        with pytest.raises(ValueError, match="non-empty string"):
            parse_time_duration(None)
        with pytest.raises(ValueError, match="non-empty string"):
            parse_time_duration(123)
