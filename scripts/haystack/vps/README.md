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

The repository is **private**, so the clone needs credentials. Pick one:

**A. SSH deploy key (recommended for a server)** — read-only, scoped to this repo:

```bash
ssh-keygen -t ed25519 -C "bt-beacon-vps" -f ~/.ssh/bt_beacon -N ''
cat ~/.ssh/bt_beacon.pub
# add it at: https://github.com/argusro/BT_Beacon/settings/keys  (Deploy keys, read-only)

cat >> ~/.ssh/config <<'EOF'
Host github-bt
  HostName github.com
  User git
  IdentityFile ~/.ssh/bt_beacon
EOF
```

```bash
REPO_URL=git@github-bt:argusro/BT_Beacon.git bash deploy.sh
```

**B. HTTPS with a fine-grained token** (`Contents: Read` on this repo):

```bash
REPO_URL=https://<token>@github.com/argusro/BT_Beacon.git bash deploy.sh
```

Prefer `GIT_ASKPASS`/a credential helper over putting the token in the URL — it
ends up in shell history and in `.git/config`.

**C. By hand** (no script):

```bash
git clone --filter=blob:none --sparse --depth 1 https://github.com/argusro/BT_Beacon.git ~/bt-beacon
cd ~/bt-beacon
git sparse-checkout set scripts      # --sparse leaves only root files until this runs
ls                                   # -> scripts/
bash scripts/haystack/vps/deploy.sh
```

`--sparse` alone checks out just the top-level files (`README.md`,
`platformio.ini`), which is why `scripts/` appears only after the
`sparse-checkout set` step.

`deploy.sh` defaults `REPO_URL` to
`https://github.com/argusro/BT_Beacon.git` and `APP_DIR` to `$HOME/bt-beacon`
(no `sudo` needed — `/opt` would require root, which makes the `scp` of your
keys awkward), so on a box with cached credentials it is just:

```bash
bash deploy.sh          # first run: clone + build + start
bash deploy.sh          # later: fetch, reset, rebuild changed services
```

It prints the resolved repo URL first, so you can see what it is about to use.

## First run: Apple login

The endpoint needs an Apple session once:

```bash
cd ~/bt-beacon/scripts/haystack/vps
docker compose run --rm endpoint
```

It asks for Apple ID → password → trusted-device code, then writes
`auth.json` into the `mh-data` volume. Re-running is only needed if Apple
invalidates the session.

## Keys

Private keys are **not in the repository**. Copy the ring from your workstation:

```bash
scp keys/beacon_keys.json <vps>:~/bt-beacon/keys/
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

- **`endpoint` keeps restarting right after a fresh deploy** — there is no
  `auth.json` yet. The container starts, tries to prompt for the Apple ID, gets
  EOF (no TTY under `up -d`), and exits. Run the interactive login once:

  ```bash
  docker compose stop endpoint
  docker compose run --rm endpoint      # Apple ID + password + trusted-device code
  docker compose up -d
  ```

  Check whether a session already exists:

  ```bash
  docker run --rm -v bt-beacon_mh-data:/d alpine ls -l /d
  # auth.json present -> no login needed
  ```
- **First query fails for ~10 s after `up`** — the endpoint retries Anisette
  every 10 s; harmless startup race.
- **`-80045`** — Anisette backend is not macOS.
- **`status 1` from `loginDelegates` / only `mmeAuthToken`** — same cause:
  Windows/Android ADI.
- **Dashboard 401** — basic auth is on; credentials are in `.env`.
- **Empty map** — no reports yet for any slot. Apple only keeps ~7 days, and
  reports only appear when an iPhone (not the owner's, ideally) sees the beacon.
