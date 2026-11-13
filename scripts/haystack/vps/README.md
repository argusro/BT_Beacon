# Watcher deployment (VPS)

This directory holds everything needed to run the **report watcher** on a server:
the Apple-authenticated endpoint, the Anisette backend, and the map dashboard.

The beacon firmware is not needed here — the tag keeps broadcasting on its own.

## Services

| Service | Image | Port | Purpose |
| --- | --- | --- | --- |
| `anisette` | `ghcr.io/fdkevin0/anisette-server-rs` (`--backend macos`) | internal 6969 | Apple ADI identity (macOS is the only backend that yields `searchPartyToken`) |
| `endpoint` | built from `scripts/haystack/Dockerfile` | internal 6176 | Apple login + report fetching (patched for the Oct-2026 changes) |
| `dashboard` | built from `scripts/haystack/dashboard.Dockerfile` | **8099** | map, history, Google Maps button, JSON API |
| `caddy` | `caddy:2-alpine` | 8081 / 8443 | optional TLS, profile `tls` |

Only the dashboard is published. `6176` and `6969` stay on the compose network.

## Deploy

```bash
# on the VPS
git clone --filter=blob:none --sparse --depth 1 https://github.com/argusro/BT_Beacon.git /opt/bt-beacon
cd /opt/bt-beacon
git sparse-checkout set scripts/haystack scripts/map_server.py scripts/decrypt_reports.py scripts/web
bash scripts/haystack/vps/deploy.sh
```

Or simply run the script once it exists on the box — it performs the sparse
checkout itself and re-syncs on every later invocation:

```bash
bash deploy.sh
# ... later, to update:
bash deploy.sh
```

`deploy.sh` does a sparse checkout of only the watcher paths, creates `.env`
with a random dashboard password on first run, then `docker compose up -d
--build` (only changed services are recreated).

## First run: Apple login

The endpoint needs an Apple session once:

```bash
cd /opt/bt-beacon/scripts/haystack/vps
docker compose run --rm endpoint
```

It asks for Apple ID → password → trusted-device code, then writes
`auth.json` into the `mh-data` volume. Re-running is only needed if Apple
invalidates the session.

## Keys

Private keys are **not in the repository**. Copy the ring from your workstation:

```bash
scp keys/beacon_keys.json <vps>:/opt/bt-beacon/keys/
```

The dashboard mounts `../keys` read-only at `/keys` and reads
`/keys/beacon_keys.json`, so all 96 rotation slots are queried.

If you rotate/regenerate the ring locally, copy the new file and restart:

```bash
docker compose restart dashboard
```

## Development: no rebuild per change

`docker-compose.local.yml` mounts the working tree:

```
scripts/map_server.py      -> /app/scripts/map_server.py
scripts/decrypt_reports.py -> /app/scripts/decrypt_reports.py
scripts/web                -> /app/scripts/web
```

- `index.html` is re-read on **every request** → edit and refresh the browser.
- Python changes → `docker compose restart dashboard` (no image build).

`docker-compose.yml` (production) bakes the files into the image instead.

## TLS

Optional profile, useful only if you have a hostname and free 80/443:

```bash
docker compose --profile tls up -d
```

Ports are `${HTTP_PORT:-8081}` / `${HTTPS_PORT:-8443}` because 80/443 are often
already taken. Without a domain, skip it and reach `http://<server>:8099` over
Tailscale/WireGuard.

## Troubleshooting

- **First query fails for ~10 s after `up`** — the endpoint retries Anisette
  every 10 s; harmless startup race.
- **`-80045`** — Anisette backend is not macOS.
- **`status 1` from `loginDelegates` / only `mmeAuthToken`** — same cause:
  Windows/Android ADI.
- **Dashboard 401** — basic auth is on; credentials are in `.env`.
- **Empty map** — no reports yet for any slot. Apple only keeps ~7 days, and
  reports only appear when an iPhone (not the owner's, ideally) sees the beacon.
