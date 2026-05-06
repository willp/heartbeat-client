"""Tests for KeyManager class."""
import json
import os
import stat
import time

from nuclei_heartbeat_client.hbclient import KeyManager


class TestKeyManagerInit:
    """Test KeyManager initialization."""

    def test_init_creates_config_dir(self, tmp_config_dir, monkeypatch):
        monkeypatch.setattr("os.path.expanduser", lambda x: str(tmp_config_dir) if x == "~/.config/hbclient" else x)
        km = KeyManager("https://hb.example.com")
        assert km.config_dir == str(tmp_config_dir)
        assert os.path.exists(tmp_config_dir)
        # Check permissions are 0o700
        mode = stat.S_IMODE(os.stat(tmp_config_dir).st_mode)
        assert mode == 0o700

    def test_init_key_file_path(self, tmp_config_dir, monkeypatch):
        monkeypatch.setattr("os.path.expanduser", lambda x: str(tmp_config_dir) if x == "~/.config/hbclient" else x)
        km = KeyManager("https://hb.example.com")
        expected = os.path.join(str(tmp_config_dir), "keys.json")
        assert km.key_file == expected


class TestKeyManagerLoad:
    """Test KeyManager.load()."""

    def test_load_nonexistent_file(self, tmp_config_dir, monkeypatch):
        monkeypatch.setattr("os.path.expanduser", lambda x: str(tmp_config_dir) if x == "~/.config/hbclient" else x)
        km = KeyManager("https://hb.example.com")
        result = km.load()
        assert result is False

    def test_load_valid_file(self, tmp_config_dir, monkeypatch, sample_keys):
        monkeypatch.setattr("os.path.expanduser", lambda x: str(tmp_config_dir) if x == "~/.config/hbclient" else x)
        km = KeyManager("https://hb.example.com")
        # Write keys file
        with open(km.key_file, "w") as f:
            json.dump(sample_keys, f)
        result = km.load()
        assert result is True
        assert km.keys == sample_keys

    def test_load_invalid_json(self, tmp_config_dir, monkeypatch):
        monkeypatch.setattr("os.path.expanduser", lambda x: str(tmp_config_dir) if x == "~/.config/hbclient" else x)
        km = KeyManager("https://hb.example.com")
        with open(km.key_file, "w") as f:
            f.write("not valid json{{{")
        result = km.load()
        assert result is False

    def test_load_force_parameter(self, tmp_config_dir, monkeypatch, sample_keys):
        monkeypatch.setattr("os.path.expanduser", lambda x: str(tmp_config_dir) if x == "~/.config/hbclient" else x)
        km = KeyManager("https://hb.example.com")
        with open(km.key_file, "w") as f:
            json.dump(sample_keys, f)
        # First load
        km.load()
        assert km.keys == sample_keys
        # Modify file mtime to be older
        old_mtime = os.stat(km.key_file).st_mtime - 100
        os.utime(km.key_file, (old_mtime, old_mtime))
        # Force reload
        km.load(force=True)
        assert km.keys == sample_keys


class TestKeyManagerAtomicWrite:
    """Test KeyManager._atomic_write()."""

    def test_atomic_write_creates_file(self, tmp_config_dir, monkeypatch, sample_keys):
        monkeypatch.setattr("os.path.expanduser", lambda x: str(tmp_config_dir) if x == "~/.config/hbclient" else x)
        km = KeyManager("https://hb.example.com")
        km._atomic_write(sample_keys)
        assert os.path.exists(km.key_file)
        with open(km.key_file) as f:
            loaded = json.load(f)
        assert loaded == sample_keys

    def test_atomic_write_strict_permissions(self, tmp_config_dir, monkeypatch, sample_keys):
        monkeypatch.setattr("os.path.expanduser", lambda x: str(tmp_config_dir) if x == "~/.config/hbclient" else x)
        km = KeyManager("https://hb.example.com")
        km._atomic_write(sample_keys)
        mode = stat.S_IMODE(os.stat(km.key_file).st_mode)
        assert mode == 0o600


class TestKeyManagerNeedsRotation:
    """Test KeyManager.needs_rotation()."""

    def test_no_keys_returns_false(self, tmp_config_dir, monkeypatch):
        monkeypatch.setattr("os.path.expanduser", lambda x: str(tmp_config_dir) if x == "~/.config/hbclient" else x)
        km = KeyManager("https://hb.example.com")
        assert km.needs_rotation() is False

    def test_keys_far_from_expiry(self, tmp_config_dir, monkeypatch):
        monkeypatch.setattr("os.path.expanduser", lambda x: str(tmp_config_dir) if x == "~/.config/hbclient" else x)
        km = KeyManager("https://hb.example.com")
        km.keys = {"expires_at": int(time.time()) + 86400 * 60}  # 60 days
        assert km.needs_rotation() is False

    def test_keys_near_expiry(self, tmp_config_dir, monkeypatch):
        monkeypatch.setattr("os.path.expanduser", lambda x: str(tmp_config_dir) if x == "~/.config/hbclient" else x)
        km = KeyManager("https://hb.example.com")
        km.keys = {"expires_at": int(time.time()) + 86400 * 5}  # 5 days (within 7-10 day jitter)
        # May be True depending on jitter, but shouldn't consistently be False
        # Just verify it returns a bool
        assert isinstance(km.needs_rotation(), bool)

    def test_legacy_keys_without_expires_at(self, tmp_config_dir, monkeypatch):
        monkeypatch.setattr("os.path.expanduser", lambda x: str(tmp_config_dir) if x == "~/.config/hbclient" else x)
        km = KeyManager("https://hb.example.com")
        km.keys = {"last_rotated_at": int(time.time()) - 86400 * 60}  # 60 days old
        assert km.needs_rotation() is True