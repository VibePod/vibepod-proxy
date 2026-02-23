# VibePod Proxy

HTTP(S) proxy container for capturing outbound traffic and logging to SQLite.

When used with VibePod CLI, requests are attributed to the originating container.

## Environment

- `PROXY_DB_PATH` (default `/data/proxy.db`)
- `PROXY_CONF_DIR` (default `/data/mitmproxy`)

## Usage

Build and run with a bind mount to `/data` so the database and CA certs persist.

## Container Attribution

The proxy resolves source containers via a shared `containers.json` file on the `/data` volume.
VibePod CLI writes this file after starting each agent container; the proxy addon reads it
(with mtime-based caching) to populate `source_container_id` and `source_container_name` in
`http_requests`.

File format (`/data/containers.json`):
```json
{
  "172.18.0.3": {
    "container_id": "abc123...",
    "container_name": "vibepod-claude-1a2b3c",
    "agent": "claude",
    "started_at": "2026-02-23T..."
  }
}
```
