#!/usr/bin/env bash
#
# Deploy / refresh the Find My watcher on a VPS.
#
# Only the watcher part of the repository is checked out (sparse checkout):
#   scripts/**   endpoint Dockerfile + patched client + compose + dashboard
#
# The firmware (src/, platformio.ini) is not fetched.
#
# Usage (on the VPS):
#   bash deploy.sh            deploy / update
#   bash deploy.sh login      re-run the interactive Apple login (session expired)
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
  "scripts"
)

if ! command -v docker >/dev/null 2>&1; then
  echo "!! docker is not installed" >&2
  exit 1
fi
if ! docker compose version >/dev/null 2>&1; then
  echo "!! docker compose v2 is required" >&2
  exit 1
fi

MODE="${1:-deploy}"
case "$MODE" in
  deploy|login) ;;
  *) echo "usage: bash deploy.sh [deploy|login]" >&2; exit 2 ;;
esac

# Renew the Apple session: interactive Apple ID + trusted-device code.
if [ "$MODE" = "login" ]; then
  if [ ! -d "$APP_DIR/.git" ]; then
    echo "!! $APP_DIR is not deployed yet - run 'bash deploy.sh' first" >&2
    exit 1
  fi
  cd "$APP_DIR/scripts/haystack/vps"
  docker compose up -d anisette
  docker compose stop endpoint >/dev/null 2>&1 || true
  # force a real login: the endpoint only prompts for credentials when the
  # stored token is gone (otherwise it just serves and looks like a no-op)
  echo "==> removing the stored Apple token"
  docker compose run --rm --entrypoint sh endpoint -c 'rm -f /app/endpoint/data/auth.json' \
    || echo "!! could not remove auth.json"
  echo "==> interactive Apple login (Ctrl+C when it says 'serving at :6176')"
  docker compose run --rm endpoint || true
  docker compose up -d
  docker compose ps
  exit 0
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
DASH_USER="${DASHBOARD_USER:-user}"
if [ ! -f .env ]; then
  PASS="$(head -c 32 /dev/urandom | base64 | tr -dc 'A-Za-z0-9' | head -c 20)"
  printf 'DASHBOARD_USER=%s\nDASHBOARD_PASS=%s\n' "$DASH_USER" "$PASS" > .env
  chmod 600 .env
  echo "==> created scripts/haystack/vps/.env"
  echo "    user:     $DASH_USER"
  echo "    password: $PASS"
fi

echo "==> build + restart"
docker compose up -d --build
# A new keys/*_keys.json lives in a bind mount, so compose sees no config
# change and would leave the old process running. Restarting forces the
# dashboard to re-scan the ring directory.
docker compose restart dashboard >/dev/null
docker compose ps
echo
echo "dashboard: http://<server>:8099  (credentials in .env)"
echo "first run? log in to Apple once:"
echo "  bash deploy.sh login"
