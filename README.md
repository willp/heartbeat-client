# nuclei-heartbeat-client

A secure, high-reliability heartbeat client for monitoring your systems
using nuclei-heartbeat-backend and nuclei-heartbeat-watcher

## Installation

```bash
pip install nuclei-heartbeat-client
```

## Quick Start

### As a library

```python
from nuclei_heartbeat_client import HbClient, HbConfig

config = HbConfig(server="hb.example.com", serverport=8333)
client = HbClient(name="my-service", interval=60, config=config)
client.send(task="deployment-complete")
```

### From the CLI

```bash
# Enroll via OAuth
nuclei-heartbeat-client --server-url https://hb.example.com:8333 login

# Check enrollment status
nuclei-heartbeat-client --server-url https://hb.example.com:8333 status

# Send a heartbeat
nuclei-heartbeat-client send --app my-service --task deploy --interval 60
```

## Features

- **AES-GCM encrypted UDP transport** with CRC32 integrity
- **OAuth Device Flow** for key management
- **Transparent DNS resolution** with configurable refresh intervals
- **Deterministic key rotation** with jitter to prevent thundering herd
- **Atomic file I/O** for crash-safe credential storage
- **Human-readable duration parsing** (e.g., `6h`, `2.5d`, `3w`)

## Configuration

The `HbConfig` dataclass provides the following configurable options:

| Attribute | Type | Default | Description |
|-----------|------|---------|-------------|
| `server` | str | `"hb"` | Heartbeat server hostname (UDP) |
| `serverport` | int | `8333` | Heartbeat server UDP port |
| `debug` | bool | `False` | Enable verbose debug logging |
| `MINIMUM_INTERVAL_SEC` | int | `30` | Minimum interval between heartbeats |
| `DNS_REFRESH_SEC` | int | `14400` | DNS cache TTL (4 hours) |
| `ALERT_INTERVAL_MULTIPLIER_LOW` | float | `2.25` | Alert threshold multiplier for intervals < 1 day |
| `ALERT_INTERVAL_MULTIPLIER_HIGH` | float | `1.25` | Alert threshold multiplier for intervals >= 1 day |
| `DUPE_SEND_DELAY_SEC` | float \| None | `None` | Delay before duplicate send (clamped to 1.0-5.0s) |

## CLI Reference

```
nuclei-heartbeat-client [--server SERVER] [--serverport PORT] [--server-url URL] COMMAND
```

### Global Options

- `--server`: UDP server hostname (default: hb)
- `--serverport`: UDP server port (default: 8333)
- `--server-url`: HTTPS URL for OAuth/key management (default: https://server:serverport)

### Commands

#### login

Enroll this device via OAuth Device Flow.

```
nuclei-heartbeat-client login
```

Prompts the user to visit a verification URL and enter a code, then polls for approval.

#### status

Show current key status (key ID, expiration).

```
nuclei-heartbeat-client status
```

#### logout

Revoke credentials on the server and delete local key file.

```
nuclei-heartbeat-client logout [--force]
```

Use `--force` to delete local keys even if the server is unreachable.

#### send

Send a heartbeat packet.

```
nuclei-heartbeat-client send --app NAME --task TASK --interval DURATION [OPTIONS]
```

Required arguments:
- `--app`, `-a NAME`: Application name
- `--task`, `-t TASK`: Task name
- `--interval`, `-i DURATION`: Heartbeat interval (e.g., `60`, `1h`, `2.5d`)

Optional arguments:
- `--alert-after`, `-A DURATION`: Alert threshold
- `--port`, `-p PORT`: Application port
- `--version`, `-v VERSION`: Application version
- `--final-report`, `-R TEXT`: Final status message
- `--debug`, `-d`: Enable debug logging

## Development

```bash
# Install development dependencies
pip install -e ".[dev]"

# Run tests
pytest tests/

# Build distribution
python -m build
```

## License

Apache-2.0 — see [LICENSE](LICENSE)