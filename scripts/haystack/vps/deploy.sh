#!/usr/bin/env bash
#
# Deploy / refresh the Find My watcher on a VPS.
#
# Only the watcher part of the repository is checked out (sparse checkout):
#   scripts/haystack/**            endpoint Dockerfile + patched client + compose
#   scripts/map_server.py          dashboard
#   scripts/decrypt_reports.py     report decryption
#   scripts/web/**                 static site
#
# The firmware, PlatformIO config and key generation are not fetched.
#
# Usage (on the VPS):
#   bash deploy.sh
#   REPO_URL=git@github-bt:argusro/BT_Beacon.git bash deploy.sh
#
# The repository is private. Either add an SSH deploy key (read-only) and use an
# ssh URL, or pass a token URL:
#   REPO_URL=https://<token>@github.com/argusro/BT_Beacon.git bash deploy.sh
#
# Environment:
#   REPO_URL   default https://github.com/argusro/BT_Beacon.git
#   APP_DIR    default $HOME/bt-beacon (no sudo needed; override if you prefer)
#   BRANCH     default master
#
# First run also creates scripts/haystack/vps/.env with a random dashboard
# password. Copy keys/beacon_keys.json from your workstation afterwards - the
# private keys are intentionally not in the repository.
set -euo pipefail

REPO_URL="${REPO_URL:-https://github.com/argusro/BT_Beacon.git}"
APP_DIR="${APP_DIR:-$HOME/bt-beacon}"
BRANCH="${BRANCH:-master}"

SPARSE_PATHS=(
  "scripts/haystack"
  "scripts/map_server.py"
  "scripts/decrypt_reports.py"
  "scripts/web"
)

if ! command -v docker >/dev/null 2>&1; then
  echo "!! docker is not installed" >&2
  exit 1
fi
if ! docker compose version >/dev/null 2>&1; then
  echo "!! docker compose v2 is required" >&2
  exit 1
fi

echo "==> repo    : $REPO_URL"
echo "==> branch  : $BRANCH"
echo "==> app dir : $APP_DIR"

if [ ! -d "$APP_DIR/.git" ]; then
  echo "==> sparse clone"
  mkdir -p "$(dirname "$APP_DIR")"
  git clone --filter=blob:none --sparse --depth 1 --branch "$BRANCH" \
    "$REPO_URL" "$APP_DIR" || {
      echo "!! clone failed." >&2
      echo "   The repo is private: set REPO_URL to an SSH deploy key or a token URL." >&2
      echo "   e.g. REPO_URL=git@github-bt:argusro/BT_Beacon.git bash deploy.sh" >&2
      exit 1
    }
  cd "$APP_DIR"
  git sparse-checkout set "${SPARSE_PATHS[@]}"
else
  echo "==> update $APP_DIR"
  cd "$APP_DIR"
  git sparse-checkout set "${SPARSE_PATHS[@]}" >/dev/null
  git fetch --depth 1 origin "$BRANCH"
  git reset --hard "origin/$BRANCH"
fi

cd "$APP_DIR/scripts/haystack/vps"

# Private keys never live in the repo.
if [ ! -f "$APP_DIR/keys/beacon_keys.json" ]; then
  mkdir -p "$APP_DIR/keys"
  echo "!! $APP_DIR/keys/beacon_keys.json is missing." >&2
  echo "   copy it from your workstation:" >&2
  echo "     scp keys/beacon_keys.json <vps>:$APP_DIR/keys/" >&2
  exit 1
fi

# Dashboard credentials.
if [ ! -f .env ]; then
  PASS="$(head -c 32 /dev/urandom | base64 | tr -dc 'A-Za-z0-9' | head -c 20)"
  printf 'DASHBOARD_USER=argus\nDASHBOARD_PASS=%s\n' "$PASS" > .env
  chmod 600 .env
  echo "==> created scripts/haystack/vps/.env"
  echo "    user:     argus"
  echo "    password: $PASS"
fi

echo "==> build + restart"
docker compose up -d --build
echo
docker compose ps
echo
echo "dashboard: http://<server>:8099  (credentials in .env)"
echo "first run? log in to Apple once:"
echo "  docker compose run --rm endpoint"
