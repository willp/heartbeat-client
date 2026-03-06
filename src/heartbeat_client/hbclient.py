#!/usr/bin/python3 -u
__all__ = ["HbClient", "HbConfig"]

"""
Heartbeat Client (hbclient) Module
==================================
A secure, high-reliability heartbeat client designed to send status updates 
to a central monitoring server.

Key Features:
-------------
- **Security**: Uses AES-GCM encryption for UDP packets with CRC32 integrity checks.
- **Authentication**: Implements OAuth Device Flow for automatic key rotation.
- **Resilience**: Transparent DNS resolution, jittered retries, and atomic file I/O 
  to handle network instability or crashes gracefully.
- **Thread Safety**: File locking (fcntl) ensures safe multi-process access to keys.

Usage:
------
    from heartbeat_client.hbclient import HbClient, HbConfig
    
    # Basic usage
    client = HbClient(name="my-app", interval=60)
    client.send(task="startup")
"""

import os
import random
import re
import sys
import json
import time
import socket
import struct
import zlib
import fcntl
import urllib.request
import urllib.error
from dataclasses import dataclass

try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
except ImportError:
    print("ERROR: Missing required cryptography library.", file=sys.stderr)
    print("Please run: pip install cryptography", file=sys.stderr)
    sys.exit(1)

@dataclass
class HbConfig:
    """
    Configuration settings for the Heartbeat Client.

    This dataclass defines default thresholds and intervals for heartbeat behavior,
    network resolution frequency, and alert logic multipliers.

    Attributes:
        server (str): The hostname of the heartbeat server (UDP). Defaults to "hb".
        serverport (int): The UDP port number for the server. Defaults to 8333.
        debug (bool): If True, enables verbose logging output. Defaults to False.
        
        MINIMUM_INTERVAL_SEC (int): Hard floor (30s) for sending heartbeats to prevent 
                                    network storming. Cannot be overridden by user inputs.
        DNS_REFRESH_SEC (int): Interval in seconds between re-resolving the server's IP.
        ALERT_INTERVAL_MULTIPLIER_LOW (float): Multiplier for alert threshold when intervals < 1 day.
        ALERT_INTERVAL_MULTIPLIER_HIGH (float): Multiplier for alert threshold when intervals >= 1 day.
        DUPE_SEND_DELAY_SEC (int|None): Optional delay before attempting a duplicate send 
                                        if the first fails or for redundancy.
    """

    server: str = "hb"
    serverport: int = 8333
    debug: bool = False
    MINIMUM_INTERVAL_SEC: int = 30
    DNS_REFRESH_SEC: int = 4 * 60 * 60
    ALERT_INTERVAL_MULTIPLIER_LOW = 2.25
    ALERT_INTERVAL_MULTIPLIER_HIGH = 1.25
    DUPE_SEND_DELAY_SEC = None

default_hb_config = HbConfig()

class KeyManager:
    """
    Manages encryption keys and secure credentials for the client session.

    This class handles the lifecycle of API tokens and AES secrets, ensuring they are
    stored securely on disk with strict permissions. It supports atomic writes to 
    prevent corruption during crashes and implements thread-safe loading using file locks.

    Features:
        - **Atomic Writes**: Uses a temporary file + `os.replace` pattern to ensure 
          the key file is never left in a partial state.
        - **Hot-Reload**: Checks file modification times (`mtime`) to avoid unnecessary 
          disk I/O if keys haven't changed.
        - **Rotation Logic**: Automatically detects near-expiration tokens (with jitter) 
          and attempts non-blocking rotation via the server's OAuth endpoint.
    """

    def __init__(self, server_url):
        """
        Initialize the Key Manager.

        Args:
            server_url (str): The base HTTPS URL of the server used for OAuth 
                              token endpoints (e.g., https://hb.example.com).
        """
        self.config_dir = os.path.expanduser("~/.config/hbclient")
        self.key_file = os.path.join(self.config_dir, "keys.json")
        self.server_url = server_url.rstrip('/')
        self.keys = {}
        self._last_mtime = 0
        
        # Create dir and explicitly lock it down to owner-only (drwx------)
        os.makedirs(self.config_dir, exist_ok=True)
        os.chmod(self.config_dir, 0o700)

    def load(self, force=False):
        """
        Load key material from disk into memory.

        Optimized for performance by checking the file's modification time (`mtime`). 
        If the file hasn't changed since the last load and `force` is False, 
        it returns immediately without reading the disk.

        Args:
            force (bool): If True, forces a re-read from disk even if mtime matches.
                          Used during login/logout or manual refresh operations.
        
        Returns:
            bool: True if keys were successfully loaded or are already current; 
                  False if the file is missing, unreadable, or invalid JSON.
        """
        if not os.path.exists(self.key_file): return False
        mtime = os.stat(self.key_file).st_mtime
        if not force and mtime <= self._last_mtime: return True
        try:
            with open(self.key_file, 'r') as f:
                self.keys = json.load(f)
            self._last_mtime = mtime
            return True
        except (json.JSONDecodeError, IOError):
            return False

    def _atomic_write(self, data):
        """
        Write key data to disk atomically with strict file permissions.

        This method ensures that the `keys.json` file is never left in a corrupted 
        or partial state. It writes to a temporary file with mode 0o600 (read/write 
        owner only), flushes and syncs the data, then atomically renames it over 
        the original.

        Args:
            data (dict): The dictionary containing keys like 'access_token', 
                         'aes_secret', 'key_id', etc.
        
        Raises:
            OSError: If the system fails to create or write to the temporary file.
        """
        tmp_file = self.key_file + ".tmp"
        
        # Bypass default umask: force file creation with strict owner-only read/write
        flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
        mode = 0o600  # -rw-------
        fd = os.open(tmp_file, flags, mode)
        
        with open(fd, 'w') as f:
            json.dump(data, f)
            f.flush()
            os.fsync(f.fileno())
            
        # Atomic replace preserves the strict permissions of the tmp file
        os.replace(tmp_file, self.key_file)
        self._last_mtime = os.stat(self.key_file).st_mtime

    def needs_rotation(self):
        """
        Determine if the current keys are near expiration and require rotation.

        Uses a randomized jitter window (7-10 days before expiry) to prevent 
        "thundering herd" problems where many clients try to rotate at the exact 
        same moment when a global token expires.

        Returns:
            bool: True if immediate or near-term rotation is required; False otherwise.
        """
        if not self.keys: return False
        
        expires_at = self.keys.get("expires_at")
        if not expires_at:
            # Legacy fallback if an old file exists without the field
            age = time.time() - self.keys.get("last_rotated_at", 0)
            return age > (30 * 86400)
            
        # Jitter: Rotate 7 to 10 days BEFORE the server's exact expiration
        jitter_seconds = random.uniform(7, 10) * 86400
        
        return time.time() > (expires_at - jitter_seconds)


    def rotate_optimistic(self):
        """
        Perform a non-blocking key rotation using the OAuth Device Flow.

        This method attempts to refresh credentials by exchanging the current 
        `device_code` for a new set of tokens and AES secrets. It does not block 
        indefinitely; if the server is unreachable or takes too long, the client 
        continues operating with existing keys until they truly expire.

        Workflow:
            1. Check for an existing `access_token` to validate current session.
            2. Call `/api/auth/token/refresh/`.
            3. If successful, update local cache and trigger atomic write.
            4. If failed (network/auth), silently ignore to ensure high availability.
        """
        if not os.path.exists(self.key_file): return
        try:
            f = open(self.key_file, 'a+')
            fcntl.flock(f, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except (BlockingIOError, IOError):
            return # Another process is rotating right now
            
        try:
            f.seek(0)
            current_keys = json.load(f)
            req = urllib.request.Request(
                f"{self.server_url}/api/auth/token/rotate/",
                headers={'Authorization': f"Bearer {current_keys.get('access_token')}"},
                method='POST'
            )
            resp = urllib.request.urlopen(req, timeout=3)
            new_data = json.loads(resp.read().decode())
            current_keys.update({
                "access_token": new_data["access_token"],
                "aes_secret": new_data["aes_secret"],
                "key_id": new_data["key_id"],
                "expires_at": new_data.get("expires_at"),                
                "last_rotated_at": int(time.time())
            })
            self._atomic_write(current_keys)
            self.keys = current_keys
        except Exception:
            pass # Fail open! Data plane will continue with old keys.
        finally:
            fcntl.flock(f, fcntl.LOCK_UN)
            f.close()


default_hb_config = HbConfig()

class HbClient:
    """
    Initialize the Heartbeat Client with network and application parameters.

    This class orchestrates the heartbeat cycle, including DNS resolution, 
    key management, payload encryption, and UDP transmission.

    Args:
        name (str): The application or service name identifying this client.
        interval (int): The expected interval between heartbeats in seconds.
        alert_after (int | None): Threshold for alerting if no heartbeat is received. 
            If None, calculated based on `interval` and config multipliers.
        task (str | None): Optional specific task name associated with the heartbeat.
        version (str | None): Optional version string of the application.
        port (int | None): The listening port of the application being monitored.
        config (HbConfig | None): Configuration object for global settings (DNS, crypto, etc.).
            Defaults to a global singleton if not provided.
        blocking (bool): If True, adds a small sleep after sending to prevent tight looping.
        **kwargs: Overrides for server hostname, port, and URL construction.

    Attributes:
        cfg (HbConfig): The active configuration object.
        server_url (str): The constructed HTTPS URL for the backend API.
        myhostname (str): The fully qualified domain name of the current machine.
        server_ips (set[str]): The set of resolved IP addresses for the server.
        key_manager (KeyManager): Instance handling credential loading and rotation.
    """

    def __init__(
        self, name: str, interval: int, alert_after: int | None = None,
        task: str | None = None, version: str | None = None, port: int | None = None,
        config: HbConfig | None = None, blocking: bool = True, **kwargs,
    ):
        self.cfg = config or default_hb_config
        self.servername = kwargs.get("servername", self.cfg.server)
        self.serverport = kwargs.get("serverport", self.cfg.serverport)
        self.server_url = kwargs.get("server_url", f"https://{self.servername}:{self.serverport}")

        self.blocking_delay: float = 0.1 if blocking else 0.0
        self.interval = interval
        self.alert_after = alert_after or int(interval * (self.cfg.ALERT_INTERVAL_MULTIPLIER_LOW if interval < 86400 else self.cfg.ALERT_INTERVAL_MULTIPLIER_HIGH))
            
        self.myhostname = socket.getfqdn()
        self.server_ips: set[str] = set()
        self._last_dns_resolve = 0
        self._update_dns()

        self.name = name; self.port = port; self.task = task; self.version = version
        self._last_sent_hb = 0
        self.key_manager = KeyManager(self.server_url)

    def _update_dns(self, ignore_errors=False):
        """
        Refresh the list of IP addresses for the configured server hostname.

        This method checks if the DNS cache (stored in `_last_dns_resolve`) is stale. 
        If so, it performs a fresh `gethostbyname_ex` lookup to handle dynamic IP changes.
        
        Args:
            ignore_errors (bool): If True, suppresses exceptions and returns False on failure.
                                 If False, an assertion ensures `server_ips` remains valid.

        Returns:
            bool: True if the DNS list was successfully updated or was still fresh; 
                  False if no update occurred or an error happened with `ignore_errors=True`.
        """
        if time.time() - self._last_dns_resolve < self.cfg.DNS_REFRESH_SEC: return False
        try:
            if self.cfg.debug:
                print(f"HbClient DEBUG: refreshing DNS lookup for {self.servername}... ", end='')
            _, _, new_server_ips = socket.gethostbyname_ex(self.servername)
            if new_server_ips:
                if self.cfg.debug:
                    if set(new_server_ips) == self.server_ips:
                        print(f' no changes ({len(self.server_ips)} IPs)')
                    else:
                        print(f' updated from {self.server_ips} to -> {new_server_ips}')
                self.server_ips = set(new_server_ips)
                self._last_dns_resolve = time.time()
        except Exception as exc:
            if self.cfg.debug:
                print(f"FAILED DNS lookup: {exc}")
            if not ignore_errors: assert self.server_ips
            else: return False
        return True

    def make_message(self):
        """
        Construct the raw heartbeat metadata dictionary.

        Builds a JSON-compatible dict containing essential client identification and status data.
        
        Returns:
            dict: A dictionary with keys for hostname (h), name (n), interval (i), 
                  timestamp (@), alert threshold (!), and optional task/version/port fields.
        """
        metadata = {"h": self.myhostname, "n": self.name, "i": self.interval, "@": int(time.time()), "!": int(self.alert_after)}
        if self.task: metadata["t"] = self.task
        if self.version: metadata["v"] = self.version
        if self.port is not None: metadata["p"] = self.port
        return metadata

    def send(self, final_report: str | None = None, strict_interval=False):
        """
        Construct, encrypt, and transmit the heartbeat packet via UDP.

        This is the core execution method. It performs the following steps:
        1. Refreshes DNS if necessary.
        2. Enforces minimum interval constraints to prevent flooding.
        3. Loads keys from disk and triggers rotation if expiration is near.
        4. Serializes metadata (and optional final report) to JSON.
        5. Encrypts the payload using AES-GCM if valid keys exist; otherwise sends plaintext.
        6. Packs the binary packet with headers (Magic, Version, KeyID), Nonce, and CRC32.
        7. Sends the packet to all known server IPs. Implements a "duplex" send strategy 
           for reliability by sending twice with a delay if configured.

        Args:
            final_report (str | None): An optional status message to include at the end of the session.
                                      If longer than 1024 chars, it is truncated and marked.
            strict_interval (bool): If True, strictly enforces the configured `interval` 
                                   rather than the minimum safety interval.

        Returns:
            bool: True if the packet was successfully sent to at least one server IP; False otherwise.
        """
        self._update_dns(ignore_errors=True)
        since_last_hb = time.time() - self._last_sent_hb
        if since_last_hb < self.cfg.MINIMUM_INTERVAL_SEC: return False
        if strict_interval and since_last_hb < self.interval: return False

        # Hot Reload & Rotate
        self.key_manager.load()
        if self.key_manager.needs_rotation():
            self.key_manager.rotate_optimistic()

        metadata = self.make_message()
        if final_report:
            metadata["f"] = final_report[0:1000] + f" (TRUNCATED {1000-len(final_report)} bytes ...)" if len(final_report) > 1000 else final_report

        json_bytes = json.dumps(metadata, allow_nan=False).encode("utf-8")
        
        # Binary Packing vs Cleartext Fallback
        if self.key_manager.keys:
            import base64
            key_id = self.key_manager.keys['key_id']
            aes_secret = base64.b64decode(self.key_manager.keys['aes_secret'])
            nonce = os.urandom(12)
            aesgcm = AESGCM(aes_secret)
            # Encrypt payload; associated_data=None
            encrypted_data = aesgcm.encrypt(nonce, json_bytes, associated_data=None)
            
            # Header: Magic(0xDB, 0x01) + KeyID (4 bytes Big Endian)
            header = struct.pack(">BBI", 0xDB, 0x01, key_id)
            payload_without_crc = header + nonce + encrypted_data
            # Append CRC32 checksum
            final_packet = payload_without_crc + struct.pack(">I", zlib.crc32(payload_without_crc) & 0xFFFFFFFF)
        else:
            # Fallback to cleartext if keys are missing (fail-open)
            final_packet = json_bytes 

        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(None)  # Blocking send
        
        def deliver_it():
            was_sent = False
            for dest_ip in self.server_ips:
                try:
                    sock.sendto(final_packet, (dest_ip, self.serverport))
                    was_sent = True; self._last_sent_hb = time.time()
                except socket.timeout: pass   # Expected for unreachable hosts in this context
            return was_sent

        # Primary send attempt
        was_sent = deliver_it()

        # Optional "Duplex" send for redundancy
        if self.cfg.DUPE_SEND_DELAY_SEC:
            time.sleep(min(self.cfg.DUPE_SEND_DELAY_SEC, 1.0))
            was_sent = was_sent or deliver_it()
            
        time.sleep(self.blocking_delay)
        return was_sent
    
def cmd_login(args):
    """
    Execute the OAuth Device Flow to enroll the client with the server.

    This function initiates the authentication process:
    1. Requests a `device_code` and `user_code` from the server.
    2. Prompts the user to visit a URL and enter the code.
    3. Polls the server for approval status using the device code.
    4. Once approved, retrieves the access token and secrets, then saves them atomically.

    Args:
        args (Namespace): Parsed command-line arguments containing `server_url`.
    
    Raises:
        SystemExit: If the user cancels, the server is unreachable, or authentication fails.
    """
    server_url = args.server_url.rstrip('/')
    km = KeyManager(server_url)
    my_hostname = socket.getfqdn()
    my_username = os.getlogin() if os.geteuid() > 0 else "root"
    req = urllib.request.Request(
        f"{server_url}/api/auth/device/init/",
        data=json.dumps({"client_name": f"{my_username}@{my_hostname}"}).encode(),
        headers={'Content-Type': 'application/json'},
        method='POST'
    )
    try:
        data = json.loads(urllib.request.urlopen(req).read().decode())
    except Exception as e:
        print(f"Failed to contact server: {e}"); sys.exit(1)
        
    print(f"\n1. Please visit: {data['verification_uri']}")
    print(f"2. Enter code:   {data['user_code']}\n")
    print("Waiting for approval...", end="", flush=True)
    
    while True:
        time.sleep(data.get('interval', 5))
        print(".", end="", flush=True)
        req = urllib.request.Request(
            f"{server_url}/api/auth/device/poll/",
            data=json.dumps({"device_code": data['device_code']}).encode(),
            headers={'Content-Type': 'application/json'},
            method='POST'
        )
        try:
            success_data = json.loads(urllib.request.urlopen(req).read().decode())
            break
        except urllib.error.HTTPError as e:
            if e.code == 400:
                err_data = json.loads(e.read().decode())
                if err_data.get('error') == 'authorization_pending': continue
                else: print(f"\nAuth failed: {err_data.get('error')}"); sys.exit(1)
            print(f"\nServer error: {e}"); sys.exit(1)
            
    success_data["last_rotated_at"] = int(time.time())
    km._atomic_write(success_data)
    print(f"\n✅ Successfully enrolled! Keys saved to {km.key_file}")

def cmd_status(args):
    """
    Display the current authentication status and key expiration details.

    Loads keys from disk and prints:
    - The configured Server URL.
    - The active Key ID.
    - Time remaining until expiration, or age of the last rotation.

    Args:
        args (Namespace): Parsed command-line arguments containing `server_url`.
    """
    km = KeyManager(args.server_url)
    if not km.load():
        print("Not enrolled. Run 'hbclient login' first."); return
    print(f"Server URL: {args.server_url}")
    print(f"Active Key ID: {km.keys.get('key_id')}")
    
    expires_at = km.keys.get('expires_at')
    if expires_at:
        days_left = (expires_at - time.time()) / 86400
        print(f"Keys expire in: {days_left:.1f} days")
    else:
        age = (time.time() - km.keys.get('last_rotated_at', 0)) / 86400
        print(f"Keys last rotated: {age:.1f} days ago")


def cmd_logout(args):
    """
    Revoke credentials on the server and delete local key files.

    Ensures a clean session termination by:
    1. Calling the server's revocation endpoint with the current access token.
    2. Deleting the local `keys.json` file.

    If the server is unreachable, the operation fails unless `--force` is passed, 
    which allows local key destruction without server confirmation.

    Args:
        args (Namespace): Parsed arguments including `server_url` and optional `force`.
    
    Raises:
        SystemExit: If revocation fails and `--force` is not set.
    """
    km = KeyManager(args.server_url)
    if not km.load():
        print("No active session found.")
        return

    try:
        req = urllib.request.Request(
            f"{args.server_url.rstrip('/')}/api/auth/token/revoke/",
            headers={'Authorization': f"Bearer {km.keys.get('access_token')}"},
            method='POST'
        )
        urllib.request.urlopen(req)
        print("✅ Server successfully revoked access.")
    except Exception as e:
        print(f"❌ Server revocation failed: {e}")
        if not getattr(args, 'force', False):
            print("Aborting. The server must be reachable to securely revoke the token.")
            print("Use --force to delete local keys anyway, or check your connection.")
            sys.exit(1)
        print("⚠️ Proceeding with local key destruction due to --force flag.")

    try:
        os.remove(km.key_file)
        print("✅ Local keys destroyed.")
    except OSError:
        pass


def parse_time_duration(duration_str: str) -> int:
    """
    Parse a human-readable time duration string into seconds.
    
    Supported formats:
        - Naked numbers (e.g., "300") -> treated as seconds
        - Numbers with suffixes: s, m, h, d, w, M, y
          (seconds, minutes, hours, days, weeks, months, years)
    
    Args:
        duration_str: A string like "1h", "5m", "1.5d", "3w", "1M", "1.4y", or "300"
    
    Returns:
        An integer > 0 representing the number of seconds
        
    Raises:
        ValueError: If the input cannot be parsed or results in non-positive value
    """
    if not duration_str or not isinstance(duration_str, str):
        raise ValueError("Input must be a non-empty string")
    
    duration_str = duration_str.strip()
    
    # Define conversion factors to seconds
    conversions = {
        's': 1,           # seconds
        'm': 60,          # minutes
        'h': 3600,        # hours
        'd': 86400,       # days
        'w': 604800,      # weeks (7 * 86400)
        'M': 2592000,     # months (30 * 86400)
        'y': 31536000     # years (365 * 86400)
    }
    
    # Match number (integer or decimal) followed by optional unit suffix
    pattern = r'^(\d+(?:\.\d+)?)([smhdwMy])?$'
    match = re.match(pattern, duration_str)
    
    if not match:
        raise ValueError(
            f"Invalid duration format: '{duration_str}'. "
            "Expected a number optionally followed by a unit suffix. "
            "Valid suffixes are: s (seconds), m (minutes), h (hours), "
            "d (days), w (weeks), M (months, 30 days), y (years). "
            "Examples: '5m', '1.5h', '2d', '3w', '1M', '0.5y'"
        )
    
    value_str = match.group(1)
    unit = match.group(2) if match.group(2) else 's'  # default to seconds
    
    try:
        value = float(value_str)
    except ValueError as e:
        raise ValueError(f"Invalid numeric value '{value_str}': {e}")
    
    if value <= 0:
        raise ValueError(
            f"Duration value must be greater than 0, got {value}"
        )
    
    seconds = value * conversions[unit]
    
    # Convert to integer (truncates decimal part)
    result = int(seconds)
    
    if result <= 0:
        raise ValueError(
            f"Calculated duration results in non-positive value. "
            f"Input '{duration_str}' equals {seconds} seconds, which truncates to {result}"
        )
    
    return result

def main():
    """
    Entry point for the CLI application.

    Handles argument parsing, legacy command interpolation, and routing to specific 
    sub-commands (login, status, logout, send).

    Features:
    - **Legacy Interceptor**: If an unknown command is passed followed by `--task`, 
      it assumes the user intended to run `send --app <command> --task ...` and 
      modifies `sys.argv` accordingly.
    - **Argument Mapping**: Maps 'help' to '-h' for better UX.
    - **Subparser Logic**: Defines specific arguments for each mode (e.g., `--app` and 
      `--task` are required for the `send` command).
    """
    # --------------------------------------------------------------------
    import argparse

    # --- THE STRICT LEGACY INTERCEPTOR ---
    known_commands = ['login', 'send', 'status', 'logout', '-h', '--help', 'help']
    
    if len(sys.argv) > 1 and sys.argv[1] not in known_commands and not sys.argv[1].startswith('-'):
        # ONLY intercept if --task is explicitly provided
        if '--task' in sys.argv:
            app_name = sys.argv.pop(1)
            sys.argv.insert(1, 'send')
            sys.argv.insert(2, '--app')
            sys.argv.insert(3, app_name)
            
    # Transparently map 'help' to '-h' for better UX
    if len(sys.argv) > 1 and sys.argv[1] == 'help':
        sys.argv[1] = '-h'

    parser = argparse.ArgumentParser(description=f"Heartbeat Client Utility (from: {socket.getfqdn()})")
    parser.add_argument("--server", default=default_hb_config.server, help="UDP Server hostname")
    parser.add_argument("--serverport", type=int, default=default_hb_config.serverport, help="UDP Server port")
    parser.add_argument("--server-url", default=None, help="HTTPS URL for key management")
    
    subparsers = parser.add_subparsers(dest="command", required=True)
    
    p_login = subparsers.add_parser("login", help="Enroll this device via OAuth Device Flow")
    p_status = subparsers.add_parser("status", help="Show current key status")

    p_logout = subparsers.add_parser("logout", help="Revoke keys and delete local config")
    p_logout.add_argument("--force", action="store_true", help="Force local logout even if server is unreachable")

    p_send = subparsers.add_parser("send", help="Send a heartbeat")
    p_send.add_argument("--app", "-a", required=True, help="App name")
    p_send.add_argument("--task", "-t", required=True, help="Task name") # <--- NOW STRICTLY REQUIRED
    p_send.add_argument("--interval", "-i", required=True, type=str, default=60, help="Heartbeat interval in seconds or human durations e.g. 6h 2.5d 3w ...")
    p_send.add_argument("--alert-after", "-A", type=str, help="Alert threshold in seconds or human durations e.g. 12h 6.25d 11w ...")
    p_send.add_argument("--port", "-p", type=str, help="App port (optional)")
    p_send.add_argument("--version", "-v", help="Version string for the app (optional)")
    p_send.add_argument("--final-report", "-R", help="Send a final status message and exit, use double quotes to include spaces")
    p_send.add_argument("--debug", "-d", action='store_true', default=False)

    args = parser.parse_args()
    if not args.server_url:
        args.server_url = f"https://{args.server}:{args.serverport}"

    if args.command == "login": 
        cmd_login(args)
    elif args.command == "status": 
        cmd_status(args)
    elif args.command == "logout": 
        cmd_logout(args)
    elif args.command == "send":
        client = HbClient(
            name=args.app, interval=parse_time_duration(args.interval), alert_after=parse_time_duration(args.alert_after) if args.alert_after else None,
            task=args.task, version=args.version, port=args.port,
            servername=args.server, serverport=args.serverport, server_url=args.server_url,
            config=HbConfig(debug=args.debug)
        )
        if not client.send(final_report=args.final_report):
            sys.exit(1)

if __name__ == "__main__":
    main()

