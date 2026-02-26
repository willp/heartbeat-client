import socket, time
import json

class HbDefaults:
    SERVER: str = 'hb'
    PORT: int = 3333
    #
    #
    # drop hb send() calls if called more frequently than this
    MINIMUM_INTERVAL_SEC: int = 30

class HbClient:
    def __init__(
        self,
        name: str,  # app name!  part of unique identifier
        interval: int,
        task: str | None = None,
        version: str | None = None,
        port: int|None = None,
        servername: str = HbDefaults.SERVER,
        serverport: int = HbDefaults.PORT,
        blocking: bool = True,
    ):
        self.servername = servername
        self.serverport = serverport
        self.blocking = blocking
        self.interval = interval
        self.myhostname = socket.getfqdn()

        # set metadata
        self.name = name
        self.port = port
        self.task = task
        self.version = version

        # Cache the hostname's IP in the object
        _, _, self.server_ips = socket.gethostbyname_ex(self.servername)

        # Record the create time of the object
        self._create_time = time.time()
        self._last_sent_hb = 0

    def make_message(self):
        # Make a metadata dictionary to a JSON string and encode it as bytes
        metadata: dict[str, str|int|None] = {
            'h': self.myhostname,
            'n': self.name,
            'i': self.interval,
        }
        if self.task:
            metadata['t'] = self.task
        if self.version:
            metadata['v'] = self.version
        if self.port is not None:
            metadata['p'] = self.port
        return metadata

    def send(self, strict_interval=False):
        """Creates a UDP packet and sends it to the target IP (or IPs if the DNS A record resolved to more than one IP)."""
        since_last_hb = time.time() - self._last_sent_hb
        if since_last_hb < HbDefaults.MINIMUM_INTERVAL_SEC:
            return
        if strict_interval and since_last_hb < self.interval:
            return
        # Create a socket object
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        metadata = self.make_message()
        json_bytes = json.dumps(metadata).encode('utf-8')

        # Set the UDP destination address and port
        for dest_ip in self.server_ips:
            dest_addr = (dest_ip, self.serverport)
            # Send the UDP packet to the target IP address and port
            sock.sendto(json_bytes, dest_addr)
        self._last_sent_hb = time.time()
        #
        time.sleep(0.1 if self.blocking else 0)
        #

