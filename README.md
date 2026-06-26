# hb-client

A secure, high-reliability heartbeat client for monitoring your systems
using `hbserver` and `hbwatcher`.

## Project Scope

This repository contains only the Python client library and CLI for sending
heartbeat packets and managing local enrollment keys.

Related repositories:

- `hbserver` (`hb_backend`): API/authentication and key lifecycle services
- `hbwatcher` (`hb_watcher`): monitoring process that evaluates heartbeat data

## Installation

```bash
pip install hb-client
```

See [MIGRATION.md](MIGRATION.md) if upgrading from older distribution or config paths.

This installs:

- the Python package `hb_client`
- the CLI command `hbclient`

## Quick Start

### As a library

```python
from hb_client import HbClient, HbConfig

config = HbConfig(server="hb.example.com", serverport=8333)
client = HbClient(name="my-service", interval=60, config=config)
client.send(task="deployment-complete")
client.close()
```

### From the CLI

```bash
hbclient --server-url https://hb.example.com:8333 login
hbclient --server-url https://hb.example.com:8333 status
hbclient send --app my-service --task deploy --interval 60
```

## Features

- **AES-GCM encrypted UDP transport** with CRC32 integrity
- **OAuth Device Flow** for key management
- **Secure by default** with `strict_security=True`
- **Transparent DNS resolution** with configurable refresh intervals
- **Deterministic key rotation** with jitter to prevent thundering herd
- **Atomic file I/O** for crash-safe credential storage
- **Human-readable duration parsing** (e.g., `6h`, `2.5d`, `3w`)

## Configuration

Enrollment keys are stored under:

- Linux: `$XDG_CONFIG_HOME/hbclient/` or `~/.config/hbclient/`
- macOS: `~/Library/Application Support/hbclient/`
- Windows: `%APPDATA%/hbclient/`

## Security Mode (`strict_security`)

`HbClient` accepts `strict_security` (default: `True`). If enrollment is missing, construction raises `RuntimeError` with guidance to run:

```bash
hbclient --server-url https://hb.example.com:8333 login
```

## CLI Reference

```
hbclient [--server SERVER] [--serverport PORT] [--server-url URL] COMMAND
```

## Development

```bash
pip install -e ".[dev]"
make test
make pre-release
```

## Releasing

```bash
pip install -e ".[release]"
cz bump
make pre-release
python -m twine upload dist/hb_client-<version>*
```

## License

Apache-2.0 — see [LICENSE](LICENSE)
