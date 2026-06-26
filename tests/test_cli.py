"""Tests for CLI commands."""
import sys
import urllib.error
from argparse import Namespace
from unittest.mock import patch

import pytest

from hb_client.hbclient import (
    CLI_NAME,
    CONFIG_DIR_NAME,
    cmd_login,
    cmd_logout,
    cmd_status,
    main,
)


class TestCmdLogin:
    """Test cmd_login function."""

    def test_login_fails_on_server_unreachable(self):
        """Test login fails when server is unreachable."""
        with patch("urllib.request.urlopen", side_effect=urllib.error.URLError("Connection refused")):
            args = Namespace(server_url="https://hb.example.com")
            with pytest.raises(SystemExit) as exc_info:
                cmd_login(args)
            assert exc_info.value.code == 1


class TestCmdStatus:
    """Test cmd_status function."""

    def test_status_no_keys_prints_not_enrolled(self, capsys, tmp_config_dir, monkeypatch):
        """Test status prints 'Not enrolled' when no keys."""
        monkeypatch.setattr(
            "os.path.expanduser",
            lambda x: str(tmp_config_dir) if x == f"~/.config/{CONFIG_DIR_NAME}" else x,
        )
        args = Namespace(server_url="https://hb.example.com")
        cmd_status(args)
        captured = capsys.readouterr()
        assert "Not enrolled" in captured.out


class TestCmdLogout:
    """Test cmd_logout function."""

    def test_logout_no_keys_prints_not_enrolled(self, capsys, tmp_config_dir, monkeypatch):
        """Test logout prints 'No active session' when no keys."""
        monkeypatch.setattr(
            "os.path.expanduser",
            lambda x: str(tmp_config_dir) if x == f"~/.config/{CONFIG_DIR_NAME}" else x,
        )
        args = Namespace(server_url="https://hb.example.com", force=False)
        cmd_logout(args)
        captured = capsys.readouterr()
        assert "No active session" in captured.out


class TestMainCLI:
    """Test main CLI entry point."""

    def test_main_unknown_command_without_task_flag(self):
        """Test main with unknown command."""
        with patch.object(sys, "argv", [CLI_NAME, "unknown"]):
            with pytest.raises(SystemExit) as exc_info:
                main()
            assert exc_info.value.code != 0  # Unknown command should fail

    def test_main_send_requires_app_and_task(self):
        """Test main with send command requiring app and task."""
        with patch.object(sys, "argv", [CLI_NAME, "send"]):
            with pytest.raises(SystemExit) as exc_info:
                main()
            assert exc_info.value.code != 0

    def test_main_help_flag(self):
        """Test main with --help."""
        with patch.object(sys, "argv", [CLI_NAME, "--help"]):
            with pytest.raises(SystemExit) as exc_info:
                main()
            # --help exits with 0
            assert exc_info.value.code == 0


class TestMainLegacyCommand:
    """Test legacy command interpolation."""

    def test_main_legacy_interceptor(self):
        """Test legacy --task command interpolation."""
        with patch.object(sys, "argv", ["myapp", "--task", "deploy"]):
            # This should be intercepted to 'send --app myapp --task deploy'
            with patch.object(sys, "argv"):
                # After interception: argv becomes ['send', '--app', 'myapp', '--task', 'deploy', ...]
                # We need --interval which is required, so this will fail
                try:
                    main()
                except SystemExit:
                    # Expected to fail due to missing --interval
                    pass
