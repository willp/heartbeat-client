#!/usr/bin/python3 -u
#!/usr/bin/python3 -u
__all__ = ["HbClient", "HbConfig"]

import os
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
    """Handles thread-safe, multi-process key storage and atomic rotation."""
    def __init__(self, server_url):
        self.config_dir = os.path.expanduser("~/.config/hbclient")
        self.key_file = os.path.join(self.config_dir, "keys.json")
        self.server_url = server_url.rstrip('/')
        self.keys = {}
        self._last_mtime = 0
        
        # Create dir and explicitly lock it down to owner-only (drwx------)
        os.makedirs(self.config_dir, exist_ok=True)
        os.chmod(self.config_dir, 0o700)

    def load(self, force=False):
        """Fast hot-reload using st_mtime."""
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
        """Writes to a tmp file with strict 0600 permissions and atomically replaces."""
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

    def needs_rotation(self, max_age_days=30):
        if not self.keys: return False
        age = time.time() - self.keys.get("last_rotated_at", 0)
        return age > (max_age_days * 86400)

    def rotate_optimistic(self):
        """Attempts rotation but fails gracefully without blocking."""
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
        if time.time() - self._last_dns_resolve < self.cfg.DNS_REFRESH_SEC: return False
        try:
            _, _, server_ips = socket.gethostbyname_ex(self.servername)
            if server_ips:
                self.server_ips = set(server_ips)
                self._last_dns_resolve = time.time()
        except Exception:
            if not ignore_errors: assert self.server_ips
            else: return False
        return True

    def make_message(self):
        metadata = {"h": self.myhostname, "n": self.name, "i": self.interval, "@": int(time.time()), "!": int(self.alert_after)}
        if self.task: metadata["t"] = self.task
        if self.version: metadata["v"] = self.version
        if self.port is not None: metadata["p"] = self.port
        return metadata

    def send(self, final_report: str | None = None, strict_interval=False):
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
            metadata["f"] = final_report[0:1000] + f" (TRUNCATED {1000-len(final_report)} ...)" if len(final_report) > 1024 else final_report

        json_bytes = json.dumps(metadata, allow_nan=False).encode("utf-8")
        
        # Binary Packing vs Cleartext Fallback
        if self.key_manager.keys:
            import base64
            key_id = self.key_manager.keys['key_id']
            aes_secret = base64.b64decode(self.key_manager.keys['aes_secret'])
            nonce = os.urandom(12)
            aesgcm = AESGCM(aes_secret)
            encrypted_data = aesgcm.encrypt(nonce, json_bytes, associated_data=None)
            
            header = struct.pack(">BBI", 0xDB, 0x01, key_id)
            payload_without_crc = header + nonce + encrypted_data
            final_packet = payload_without_crc + struct.pack(">I", zlib.crc32(payload_without_crc) & 0xFFFFFFFF)
        else:
            final_packet = json_bytes 

        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(None)
        
        def deliver_it():
            was_sent = False
            for dest_ip in self.server_ips:
                try:
                    sock.sendto(final_packet, (dest_ip, self.serverport))
                    was_sent = True; self._last_sent_hb = time.time()
                except socket.timeout: pass
            return was_sent

        was_sent = deliver_it()
        if self.cfg.DUPE_SEND_DELAY_SEC:
            time.sleep(min(self.cfg.DUPE_SEND_DELAY_SEC, 1.0))
            was_sent = was_sent or deliver_it()
            
        time.sleep(self.blocking_delay)
        return was_sent
    
def cmd_login(args):
    server_url = args.server_url.rstrip('/')
    km = KeyManager(server_url)
    
    req = urllib.request.Request(
        f"{server_url}/api/auth/device/init/",
        data=json.dumps({"client_name": socket.getfqdn()}).encode(),
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
    km = KeyManager(args.server_url)
    if not km.load():
        print("Not enrolled. Run 'hbclient login' first."); return
    print(f"Server URL: {args.server_url}")
    print(f"Active Key ID: {km.keys.get('key_id')}")
    print(f"Keys last rotated: {(time.time() - km.keys.get('last_rotated_at', 0)) / 86400:.1f} days ago")

def cmd_logout(args):
    km = KeyManager(args.server_url)
    if km.load():
        try:
            urllib.request.urlopen(urllib.request.Request(
                f"{args.server_url.rstrip('/')}/api/auth/token/revoke/",
                headers={'Authorization': f"Bearer {km.keys.get('access_token')}"}, method='POST'
            ))
        except Exception as e: print(f"Server revocation warning: {e}")
        os.remove(km.key_file)
        print("✅ Local keys destroyed and server revoked access.")
    else: print("No active session found.")

def main():
    import argparse

    # --- THE STRICT LEGACY INTERCEPTOR ---
    known_commands = ['login', 'send', 'status', 'logout', '-h', '--help', 'help']
    
    if len(sys.argv) > 1 and sys.argv[1] not in known_commands:
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

    p_send = subparsers.add_parser("send", help="Send a heartbeat")
    p_send.add_argument("--app", required=True, help="App name")
    p_send.add_argument("--task", required=True, help="Task name") # <--- NOW STRICTLY REQUIRED
    p_send.add_argument("--port", type=int, help="App port")
    p_send.add_argument("--version", help="Version string")
    p_send.add_argument("--debug", "-d", action='store_true', default=False)
    p_send.add_argument("--interval", type=int, default=60, help="Heartbeat interval in seconds")
    p_send.add_argument("--alert-after", type=int, help="Alert threshold in seconds")
    p_send.add_argument("--final-report", help="Send a final status message and exit")

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
            name=args.app, interval=args.interval, alert_after=args.alert_after,
            task=args.task, version=args.version, port=args.port,
            servername=args.server, serverport=args.serverport, server_url=args.server_url,
            config=HbConfig(debug=args.debug)
        )
        if not client.send(final_report=args.final_report):
            sys.exit(1)

if __name__ == "__main__":
    main()