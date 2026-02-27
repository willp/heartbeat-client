#!/usr/bin/python3 -u

from dataclasses import dataclass
import socket, time
import json

@dataclass
class HbConfig:
    server: str = "hb"
    serverport: int = 8333
    #
    #
    # drop hb send() calls if called more frequently than this
    MINIMUM_INTERVAL_SEC: int = 30
    DNS_REFRESH_SEC: int = 4 * 60 * 60
    ALERT_INTERVAL_MULTIPLIER_LOW = 2.25   # interval of 1 day or longer
    ALERT_INTERVAL_MULTIPLIER_HIGH = 1.25  # interval less than one day

default_hb_config = HbConfig()

class HbClient:
    def __init__(
        self,
        name: str,  # app name!  part of unique identifier
        interval: int,
        alert_after:int|None = None,
        task: str | None = None,
        version: str | None = None,
        port: int | None = None,
        config: HbConfig | None = None,
        blocking: bool = True,
        **kwargs,
    ):
        self.cfg = config or default_hb_config
        self.servername = kwargs.get("servername", self.cfg.server)
        self.serverport = kwargs.get("serverport", self.cfg.serverport)

        self.blocking_delay: float = 0.1 if blocking else 0.0
        self.interval = interval
        if alert_after is None:
            self.alert_after = int(interval * (
                self.cfg.ALERT_INTERVAL_MULTIPLIER_LOW
                if interval < 86400
                else self.cfg.ALERT_INTERVAL_MULTIPLIER_HIGH)
            )
        else:
            self.alert_after = alert_after
        self.myhostname = socket.getfqdn()
        self.server_ips: set[str] = set()
        self._last_dns_resolve = 0
        self._dns_resolve_interval = self.cfg.DNS_REFRESH_SEC
        self._update_dns()

        # set metadata
        self.name = name
        self.port = port
        self.task = task
        self.version = version

        # Record the create time of the object
        self._create_time = time.time()
        self._last_sent_hb = 0

    def _update_dns(self, ignore_errors=False):
        # Cache the hostname's IP in the object
        since_last_dns = time.time() - self._last_dns_resolve
        if since_last_dns < self._dns_resolve_interval:
            return False
        try:
            _, _, server_ips = socket.gethostbyname_ex(self.servername)
            if server_ips:
                self.server_ips = set(server_ips)  # de-dupes
                self._last_dns_resolve = time.time()
        except:
            if not ignore_errors:
                assert self.server_ips  # must have at least one IP
            else:
                return False
        return True

    def make_message(self):
        # Make a metadata dictionary to a JSON string and encode it as bytes
        metadata: dict[str, str | int | None] = {
            "h": self.myhostname,
            "n": self.name,
            "i": self.interval,
            "@": int(time.time()),
            "!": int(self.alert_after),
        }
        if self.task:
            metadata["t"] = self.task
        if self.version:
            metadata["v"] = self.version
        if self.port is not None:
            metadata["p"] = self.port
        return metadata

    def send(self, final_report: str | None = None, strict_interval=False):
        """Creates a UDP packet and sends it to the target IP (or IPs if the DNS A record resolved to more than one IP)."""
        self._update_dns(
            ignore_errors=True
        )  # refresh DNS once in a while, ignoring errors
        since_last_hb = time.time() - self._last_sent_hb
        if since_last_hb < self.cfg.MINIMUM_INTERVAL_SEC:
            return False
        if strict_interval and since_last_hb < self.interval:
            return False
        # Create a socket object
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(None)  # This makes it non-blocking with no timeout
        metadata = self.make_message()
        if final_report:
            if len(final_report) > 1024:
                final_report = (
                    final_report[0:1000] + f" (TRUNCATED {1000-len(final_report)} ..."
                )
            metadata["f"] = final_report
        json_bytes = json.dumps(metadata, allow_nan=False).encode("utf-8")

        # Set the UDP destination address and port
        was_sent = False
        for dest_ip in self.server_ips:
            dest_addr = (dest_ip, self.serverport)
            # Send the UDP packet to the target IP address and port
            try:
                print(f"Sending to {dest_addr}...")
                print(f"Payload: {json_bytes}")
                sock.sendto(json_bytes, dest_addr)
                was_sent = True
                self._last_sent_hb = time.time()
            except socket.timeout:
                pass  # ignore timeouts
        #
        time.sleep(self.blocking_delay)
        return was_sent

# ... (Keep your HbDefaults and HbClient class exactly as they are) ...

def _main():
    import argparse
    import sys

    parser = argparse.ArgumentParser(description=f"Heartbeat Client Utility  (sending from: {socket.getfqdn()})")

    # Identity parameters (mapping to HbClient init)
    parser.add_argument("name", help="App name (part of unique identifier)")
    parser.add_argument("--task", help="Task name (part of unique identifier)")
    parser.add_argument("--port", type=int, help="App port (part of unique identifier)")
    parser.add_argument("--version", help="Version string")

    # Timing and thresholds
    parser.add_argument("--interval", type=int, default=60, help="Heartbeat interval in seconds")
    parser.add_argument("--alert-after", type=int, help="Alert threshold in seconds")

    # Server connection
    parser.add_argument("--server", default=default_hb_config.server, help="UDP Server hostname")
    parser.add_argument("--serverport", type=int, default=default_hb_config.serverport, help="UDP Server port")

    # Final message
    parser.add_argument("--final-report", help="Send a final status message and exit")

    args = parser.parse_args()

    # Initialize client using your existing logic
    client = HbClient(
        name=args.name,
        interval=args.interval,
        alert_after=args.alert_after,
        task=args.task,
        version=args.version,
        port=args.port,
        servername=args.server,
        serverport=args.serverport
    )

    # Send the heartbeat
    success = client.send(final_report=args.final_report)

    if not success:
        # Exit with 1 if rate-limited or DNS failed
        sys.exit(1)

if __name__ == "__main__":
    _main()
