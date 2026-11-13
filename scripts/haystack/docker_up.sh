#!/bin/bash
# Bring up the macless-haystack backend inside WSL2 Ubuntu.
#
# Run from Windows PowerShell:
#   wsl -d Ubuntu -u root -- bash /mnt/c/Users/argus/Documents/Code/BT_Beacon/scripts/haystack/docker_up.sh
#
# Idempotent: starts dockerd, ensures the network, the Windows-ADI anisette
# server, and the patched endpoint image. Does NOT run the endpoint, because its
# first start is interactive (Apple ID + password + SMS code).
set -e

HERE="$(cd "$(dirname "$0")" && pwd)"

# 1. docker daemon (no systemd in this WSL distro, so start it directly)
if ! pgrep dockerd >/dev/null 2>&1; then
  echo "starting dockerd..."
  nohup dockerd >/var/log/dockerd.log 2>&1 &
  for i in $(seq 1 30); do
    docker info >/dev/null 2>&1 && break
    sleep 1
  done
fi
docker info >/dev/null 2>&1 || { echo "dockerd failed to start; see /var/log/dockerd.log"; exit 1; }

# 2. shared network
docker network create mh-network >/dev/null 2>&1 || true

# 3. anisette with the MACOS ADI backend.
#    Apple binds auth to the ADI platform (Oct 2026). Android gets -80045,
#    Windows is accepted but only ever returns mmeAuthToken - no
#    searchPartyToken, which Find My report fetching needs. macOS is the only
#    backend that yields searchPartyToken.
if ! docker ps --format '{{.Names}}' | grep -qx anisette; then
  docker rm -f anisette >/dev/null 2>&1 || true
  docker run -d --restart always --name anisette \
    -p 6969:6969 \
    --volume anisette-mac-data:/data \
    --network mh-network \
    ghcr.io/fdkevin0/anisette-server-rs:latest --backend macos >/dev/null
fi

echo "waiting for anisette..."
for i in $(seq 1 40); do
  code=$(curl -s -o /dev/null -m 2 -w '%{http_code}' http://localhost:6969/ 2>/dev/null || true)
  [ -n "$code" ] && [ "$code" != "000" ] && { echo "anisette OK (HTTP $code)"; break; }
  sleep 1
done

# 4. patched endpoint image (GrandSlam identity fix)
if ! docker image inspect bt-beacon-haystack >/dev/null 2>&1; then
  echo "building patched endpoint image..."
  docker build -t bt-beacon-haystack "$HERE"
fi

echo
echo "anisette identity:"
curl -s -m 30 http://localhost:6969/v3/client_info
echo
echo
echo "next (interactive - needs your Apple ID, SMS 2FA):"
echo "  wsl -d Ubuntu -u root -- docker run --rm -it --name macless-haystack \\"
echo "      -p 6176:6176 --volume mh_data:/app/endpoint/data --network mh-network bt-beacon-haystack"
echo
echo "after 'serving at port 6176 over HTTP', Ctrl+C and start it detached:"
echo "  wsl -d Ubuntu -u root -- docker run -d --restart unless-stopped --name macless-haystack \\"
echo "      -p 6176:6176 --volume mh_data:/app/endpoint/data --network mh-network bt-beacon-haystack"
echo
docker ps --format '{{.Names}}  {{.Status}}  {{.Image}}'
