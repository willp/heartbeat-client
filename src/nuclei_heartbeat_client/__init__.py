from .hbclient import (
    HbClient,
    HbConfig,
    KeyManager,
    cmd_login,
    cmd_status,
    cmd_logout,
    parse_time_duration,
)
from importlib.metadata import version, PackageNotFoundError

try:
    __version__ = version(__name__)
except PackageNotFoundError:
    __version__ = "unknown"

__all__ = [
    "HbClient",
    "HbConfig",
    "KeyManager",
    "cmd_login",
    "cmd_status",
    "cmd_logout",
    "parse_time_duration",
    "__version__",
]
