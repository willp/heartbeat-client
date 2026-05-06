# nhbclient

A secure, high-reliability heartbeat client for monitoring your systems
using nuclei-heartbeat-backend and nuclei-heartbeat-watcher

## Project Scope

This repository contains only the Python client library and CLI for sending
heartbeat packets and managing local enrollment keys.

Related repositories:

- `nuclei-heartbeat-backend`: API/authentication and key lifecycle services
- `nuclei-heartbeat-watcher`: monitoring process that evaluates heartbeat data

## Installation

```bash
pip install nhbclient
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
nhbclient --server-url https://hb.example.com:8333 login

# Check enrollment status
nhbclient --server-url https://hb.example.com:8333 status

# Send a heartbeat
nhbclient send --app my-service --task deploy --interval 60
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

### Security Mode

The `HbClient` supports a `strict_security` parameter (default: `True`) to control the enforcement of security protocols.

- **Strict Mode (`True`)**: Enforces mandatory encryption and authentication. The client will refuse to initialize if valid, enrolled keys are not found, or if a key is expired and cannot be refreshed. This prevents accidental transmission of unauthenticated or plaintext heartbeats in sensitive environments.
- **Non-Strict Mode (`False`)**: Allows for a "bootstrap" phase. The client can operate without enrollment by sending plaintext JSON payloads, which is useful for initial setup before keys are provisioned.
- **Note**: If an enrollment exists but the key material is corrupted or invalid, the client will refuse to fall back to plaintext even in non-strict mode to prevent an insecure state.

```
nhbclient [--server SERVER] [--serverport PORT] [--server-url URL] COMMAND
```

### Global Options

- `--server`: UDP server hostname (default: hb)
- `--serverport`: UDP server port (default: 8333)
- `--server-url`: HTTPS URL for OAuth/key management (default: https://server:serverport)

### Commands

#### login

Enroll this device via OAuth Device Flow.

```
nhbclient login
```

Prompts the user to visit a verification URL and enter a code, then polls for approval.

#### status

Show current key status (key ID, expiration).

```
nhbclient status
```

#### logout

Revoke credentials on the server and delete local key file.

```
nhbclient logout [--force]
```

Use `--force` to delete local keys even if the server is unreachable.

#### send

Send a heartbeat packet.

```
nhbclient send --app NAME --task TASK --interval DURATION [OPTIONS]
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

# Install optional static type-checking dependencies
pip install -e ".[typecheck]"

# Run lints and type checks
ruff check .
mypy src

# Run tests
pytest

# Build distribution
python -m build

# Validate package metadata before uploading
twine check dist/*
```

## Releasing (Commitizen)

Versioning and tagging are managed with Commitizen.

```bash
# Install release tooling
pip install -e ".[release]"

# Ensure clean local environment
rm -rf dist/ build/ *.egg-info

# Bump version + create changelog entry + tag
cz bump

# Build and validate artifacts
python -m build
twine check dist/*

# Upload release (trusted publishing or token-based)
python -m twine upload dist/nhbclient-<version>*
```

## License

Apache-2.0 — see [LICENSE](LICENSE)