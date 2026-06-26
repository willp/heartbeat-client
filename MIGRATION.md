# Migration: hb-client naming

## PyPI and CLI

| Before | After |
|--------|-------|
| `nuclei-heartbeat-client` / `nhbclient` (PyPI) | `hb-client` |
| `nuclei-heartbeat-client` / `nhbclient` (CLI) | `hbclient` |
| `pip install nhbclient` | `pip install hb-client` |

## Python imports

```python
from hb_client import HbClient, HbConfig
```

## Config directory

Keys live at `~/.config/hbclient/` (sole path; no runtime legacy directory fallbacks).

If you used the intermediate `~/.config/nhbclient/` path from a prior release, move keys before upgrading:

```bash
mv ~/.config/nhbclient ~/.config/hbclient
```

## Cross-project names

| Role | pip install | CLI | Python import |
|------|-------------|-----|---------------|
| Client | `hb-client` | `hbclient` | `hb_client` |
| Server | `hb-server` | `hbserver` | `hb_backend` |
| Watcher | `hb-watcher` | `hbwatcher` | `hb_watcher` |
