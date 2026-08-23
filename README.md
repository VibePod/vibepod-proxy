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

## Filtering (opt-in)

The proxy reads `/data/filter.json` (hot-reloaded on change, written by
VibePod CLI — `vp proxy filter …`):

```json
{
  "mode": "open",
  "allow": ["api.anthropic.com", "*.github.com"],
  "deny": ["example.com"]
}
```

- `mode: open` (default) — no filtering; everything passes and is logged.
- `mode: allow` — only hosts matching the `allow` list pass.
- `mode: deny` — everything passes except hosts matching the `deny` list.

Patterns: `example.com` matches that host exactly; `*.example.com` matches
subdomains (not the apex). Matching is case-insensitive.

Blocked requests get a `403` (HTTPS tunnels are refused at `CONNECT`) and are
logged to `http_requests` with `blocked = 1`. A missing or malformed
`filter.json` disables filtering (fail-open).

Every logged request also records the policy that was active when it was
handled: `filter_mode` (`open`, `allow`, or `deny`) and, for blocked rows,
`block_reason` — `deny-match` (host matched the `deny` list) or `allow-miss`
(host matched nothing on the `allow` list). Rows written before this column
existed have `NULL` in both.

Additional environment variable: `PROXY_FILTER_PATH` (default `/data/filter.json`).

## License

MIT — see [LICENSE](LICENSE)
