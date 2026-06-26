from importlib.metadata import PackageNotFoundError, version

from .hbclient import (
    CLI_NAME,
    CONFIG_DIR_NAME,
    HbClient,
    HbConfig,
    KeyManager,
    cmd_login,
    cmd_logout,
    cmd_status,
    parse_time_duration,
)

try:
    __version__ = version(__name__)
except PackageNotFoundError:
    __version__ = "unknown"

__all__ = [
    "CLI_NAME",
    "CONFIG_DIR_NAME",
    "HbClient",
    "HbConfig",
    "KeyManager",
    "cmd_login",
    "cmd_status",
    "cmd_logout",
    "parse_time_duration",
    "__version__",
]
