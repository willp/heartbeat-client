"""Tests for KeyManager class."""
import json
import os
import stat
import time

from hb_client.hbclient import CONFIG_DIR_NAME, KeyManager

DEFAULT_CONFIG_PATH = f"~/.config/{CONFIG_DIR_NAME}"


def _patch_config_path(monkeypatch, config_dir):
    monkeypatch.setattr(
        "os.path.expanduser",
        lambda x: str(config_dir) if x == DEFAULT_CONFIG_PATH else x,
    )


class TestKeyManagerInit:
    """Test KeyManager initialization."""

    def test_init_sets_permissions_on_existing_config_dir(self, tmp_config_dir, monkeypatch):
        _patch_config_path(monkeypatch, tmp_config_dir)
        km = KeyManager("https://hb.example.com")
        assert km.config_dir == str(tmp_config_dir)
        assert os.path.exists(tmp_config_dir)
        mode = stat.S_IMODE(os.stat(tmp_config_dir).st_mode)
        assert mode == 0o700

    def test_init_key_file_path(self, tmp_config_dir, monkeypatch):
        _patch_config_path(monkeypatch, tmp_config_dir)
        km = KeyManager("https://hb.example.com")
        expected = os.path.join(str(tmp_config_dir), "keys.json")
        assert km.key_file == expected

    def test_fresh_install_uses_hbclient_path(self, tmp_path, monkeypatch):
        config_dir = tmp_path / CONFIG_DIR_NAME
        _patch_config_path(monkeypatch, config_dir)
        km = KeyManager("https://hb.example.com")
        assert km.config_dir == str(config_dir)
        assert km.key_file == str(config_dir / "keys.json")


class TestKeyManagerLoad:
    """Test KeyManager.load()."""

    def test_load_nonexistent_file(self, tmp_config_dir, monkeypatch):
        _patch_config_path(monkeypatch, tmp_config_dir)
        km = KeyManager("https://hb.example.com")
        result = km.load()
        assert result is False

    def test_load_valid_file(self, tmp_config_dir, monkeypatch, sample_keys):
        _patch_config_path(monkeypatch, tmp_config_dir)
        km = KeyManager("https://hb.example.com")
        with open(km.key_file, "w") as f:
            json.dump(sample_keys, f)
        result = km.load()
        assert result is True
        assert km.keys == sample_keys

    def test_load_invalid_json(self, tmp_config_dir, monkeypatch):
        _patch_config_path(monkeypatch, tmp_config_dir)
        km = KeyManager("https://hb.example.com")
        with open(km.key_file, "w") as f:
            f.write("not valid json{{{")
        result = km.load()
        assert result is False

    def test_load_force_parameter(self, tmp_config_dir, monkeypatch, sample_keys):
        _patch_config_path(monkeypatch, tmp_config_dir)
        km = KeyManager("https://hb.example.com")
        with open(km.key_file, "w") as f:
            json.dump(sample_keys, f)
        km.load()
        assert km.keys == sample_keys
        old_mtime = os.stat(km.key_file).st_mtime - 100
        os.utime(km.key_file, (old_mtime, old_mtime))
        km.load(force=True)
        assert km.keys == sample_keys


class TestKeyManagerAtomicWrite:
    """Test KeyManager._atomic_write()."""

    def test_atomic_write_creates_file(self, tmp_path, monkeypatch, sample_keys):
        config_dir = tmp_path / CONFIG_DIR_NAME
        _patch_config_path(monkeypatch, config_dir)
        km = KeyManager("https://hb.example.com")
        km._atomic_write(sample_keys)
        key_file = config_dir / "keys.json"
        assert key_file.exists()
        with open(key_file) as f:
            loaded = json.load(f)
        assert loaded == sample_keys
        assert km.config_dir == str(config_dir)
        assert km.key_file == str(key_file)

    def test_atomic_write_strict_permissions(self, tmp_config_dir, monkeypatch, sample_keys):
        _patch_config_path(monkeypatch, tmp_config_dir)
        km = KeyManager("https://hb.example.com")
        km._atomic_write(sample_keys)
        mode = stat.S_IMODE(os.stat(km.key_file).st_mode)
        assert mode == 0o600


class TestKeyManagerNeedsRotation:
    """Test KeyManager.needs_rotation()."""

    def test_no_keys_returns_false(self, tmp_config_dir, monkeypatch):
        _patch_config_path(monkeypatch, tmp_config_dir)
        km = KeyManager("https://hb.example.com")
        assert km.needs_rotation() is False

    def test_keys_far_from_expiry(self, tmp_config_dir, monkeypatch):
        _patch_config_path(monkeypatch, tmp_config_dir)
        km = KeyManager("https://hb.example.com")
        km.keys = {"expires_at": int(time.time()) + 86400 * 60}
        assert km.needs_rotation() is False

    def test_keys_near_expiry(self, tmp_config_dir, monkeypatch):
        _patch_config_path(monkeypatch, tmp_config_dir)
        km = KeyManager("https://hb.example.com")
        km.keys = {"expires_at": int(time.time()) + 86400 * 5}
        assert isinstance(km.needs_rotation(), bool)

    def test_legacy_keys_without_expires_at(self, tmp_config_dir, monkeypatch):
        _patch_config_path(monkeypatch, tmp_config_dir)
        km = KeyManager("https://hb.example.com")
        km.keys = {"last_rotated_at": int(time.time()) - 86400 * 60}
        assert km.needs_rotation() is True

    def test_expired_keys_always_need_rotation(self, tmp_config_dir, monkeypatch):
        """Expired keys should always trigger rotation to support recovery scenarios."""
        _patch_config_path(monkeypatch, tmp_config_dir)
        km = KeyManager("https://hb.example.com")
        # Key expired 30 days ago
        km.keys = {"expires_at": int(time.time()) - 86400 * 30}
        assert km.is_expired() is True
        assert km.needs_rotation() is True

    def test_expired_keys_one_second_ago(self, tmp_config_dir, monkeypatch):
        """Even freshly-expired keys should trigger rotation."""
        _patch_config_path(monkeypatch, tmp_config_dir)
        km = KeyManager("https://hb.example.com")
        km.keys = {"expires_at": int(time.time()) - 1}
        assert km.is_expired() is True
        assert km.needs_rotation() is True
