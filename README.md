# VibePod Proxy

HTTP(S) proxy container for capturing outbound traffic and logging to SQLite.

## Environment

- `PROXY_DB_PATH` (default `/data/proxy.db`)
- `PROXY_CONF_DIR` (default `/data/mitmproxy`)

## Usage

Build and run with a bind mount to `/data` so the database and CA certs persist.
