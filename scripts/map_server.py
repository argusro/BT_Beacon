#!/usr/bin/env python3
"""
Live map + persistent history for the BT_Beacon tag.

Fetches the encrypted reports, decrypts them with the local private key, merges
them into a local history file (so data survives Apple's ~7-day retention) and
serves a Leaflet map with a timeline, an "open in Google Maps" button and
home-screen install support.

The private key never leaves this process - only decrypted points are served.

Usage:
    python scripts/map_server.py
    python scripts/map_server.py --proxy https://haystack-proxy.iokzxt.workers.dev/fetch
    python scripts/map_server.py --auth user:password --port 8099
    python scripts/map_server.py --keep-days 30 --poll 5
"""

import argparse
import base64
import hashlib
import hmac
import json
import pathlib
import socket
import struct
import sys
import threading
import time
import urllib.request
import zlib
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from cryptography.hazmat.primitives.asymmetric import ec

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from decrypt_reports import decrypt_payload, load_keys  # noqa: E402

ROOT = pathlib.Path(__file__).resolve().parent.parent
AUTH = None  # (user, password) when --auth is given
WEB_DIR = ROOT / "scripts" / "web"  # served as static files, re-read per request


MANIFEST = {
    "name": "BT_Beacon",
    "short_name": "Beacon",
    "start_url": "/",
    "scope": "/",
    "display": "standalone",
    "background_color": "#1a73e8",
    "theme_color": "#1a73e8",
    "icons": [{"src": "/apple-touch-icon.png", "sizes": "180x180", "type": "image/png"}],
}


def make_icon(size: int = 180) -> bytes:
    """Blue square, white ring, red dot - a PNG built with nothing but stdlib."""
    centre = (size - 1) / 2
    outer = size * 0.40
    inner = size * 0.15

    raw = bytearray()
    for y in range(size):
        raw.append(0)  # filter: none
        for x in range(size):
            d = ((x - centre) ** 2 + (y - centre) ** 2) ** 0.5
            if d <= inner:
                raw.extend((0xD0, 0x00, 0x00, 0xFF))
            elif d <= outer:
                raw.extend((0xFF, 0xFF, 0xFF, 0xFF))
            else:
                raw.extend((0x1A, 0x73, 0xE8, 0xFF))

    def chunk(tag: bytes, data: bytes) -> bytes:
        return (struct.pack(">I", len(data)) + tag + data
                + struct.pack(">I", zlib.crc32(tag + data) & 0xFFFFFFFF))

    ihdr = struct.pack(">IIBBBBB", size, size, 8, 6, 0, 0, 0)
    return (b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", ihdr)
            + chunk(b"IDAT", zlib.compress(bytes(raw), 9)) + chunk(b"IEND", b""))


ICON = None


class History:
    """Merge decrypted points into a JSON file, deduplicated by payload."""

    def __init__(self, path: pathlib.Path, keep_days: int = 0, max_points: int = 0):
        self.path = path
        self.keep_days = keep_days
        self.max_points = max_points
        self.lock = threading.Lock()
        self.points: list[dict] = []
        if path.exists():
            try:
                self.points = json.loads(path.read_text()).get("points", [])
            except (ValueError, OSError):
                self.points = []

    def _trim(self) -> None:
        if self.keep_days:
            cutoff = (datetime.now(timezone.utc) - timedelta(days=self.keep_days)).isoformat()
            self.points = [p for p in self.points if p["when"] >= cutoff]
        if self.max_points and len(self.points) > self.max_points:
            # points are sorted oldest-first: keep the newest tail
            self.points = self.points[-self.max_points:]

    def merge(self, new_points: list[dict]) -> list[dict]:
        with self.lock:
            known = {p["id"] for p in self.points}
            changed = False
            for point in new_points:
                if point["id"] not in known:
                    self.points.append(point)
                    known.add(point["id"])
                    changed = True
            if changed:
                self.points.sort(key=lambda p: p["when"])
                self._trim()
                self.path.parent.mkdir(parents=True, exist_ok=True)
                self.path.write_text(json.dumps({"points": self.points}, indent=1))
            return list(self.points)

    def snapshot(self) -> list[dict]:
        with self.lock:
            return list(self.points)


def fetch_reports(args, hashes: list[str]) -> list[dict]:
    if args.proxy:
        url = args.proxy
        body = {"search": [{"ids": hashes}]}
    else:
        url = args.endpoint.rstrip("/") + "/"
        body = {"ids": hashes, "days": args.days}

    request = urllib.request.Request(
        url,
        data=json.dumps(body).encode(),
        headers={"Content-Type": "application/json"},
    )
    with urllib.request.urlopen(request, timeout=120) as response:
        return json.load(response).get("results", [])


def collect(args, keys: dict, history: History) -> None:
    try:
        raw = fetch_reports(args, list(keys))
    except Exception as exc:  # noqa: BLE001
        raise RuntimeError(f"fetch failed: {exc}") from exc

    fresh = []
    for report in raw:
        payload = report["payload"]
        matched = keys.get(report.get("id"))
        candidates = [matched] if matched is not None else list(keys.values())

        point = None
        for candidate in candidates:
            try:
                point = decrypt_payload(payload, candidate)
                break
            except Exception:  # noqa: BLE001
                continue
        if point is None:
            continue

        point["id"] = hashlib.sha1(payload.encode()).hexdigest()
        fresh.append(point)

    history.merge(fresh)


def build_payload(args, keys: dict, history: History) -> dict:
    try:
        collect(args, keys, history)
    except RuntimeError as exc:
        if not history.snapshot():
            return {"error": str(exc), "keep_days": args.keep_days}
    points = history.snapshot()
    return {
        "count": len(points),
        "reports": points,
        "stored_since": points[0]["when"] if points else None,
        "keep_days": args.keep_days,
        "max_points": args.max_points,
        "keys": len(keys),
    }


class Handler(BaseHTTPRequestHandler):
    keys = None
    args = None
    history = None

    def log_message(self, fmt, *a):
        pass

    def _authorised(self) -> bool:
        if not AUTH:
            return True
        header = self.headers.get("Authorization", "")
        if not header.startswith("Basic "):
            return False
        try:
            user, _, password = base64.b64decode(header[6:]).decode().partition(":")
        except Exception:  # noqa: BLE001
            return False
        return (hmac.compare_digest(user, AUTH[0])
                and hmac.compare_digest(password, AUTH[1]))

    def _send(self, code, content_type, body: bytes):
        self.send_response(code)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        if code == 401:
            self.send_header("WWW-Authenticate", 'Basic realm="beacon"')
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if not self._authorised():
            self._send(401, "text/plain", b"auth required")
            return

        if self.path.startswith("/api/reports"):
            payload = build_payload(self.args, self.keys, self.history)
            self._send(200, "application/json", json.dumps(payload).encode())
        elif self.path in ("/", "/index.html"):
            try:
                body = (pathlib.Path(WEB_DIR) / "index.html").read_bytes()
                self._send(200, "text/html; charset=utf-8", body)
            except OSError as exc:  # noqa: BLE001
                self._send(500, "text/plain", f"cannot read index.html: {exc}".encode())
        elif self.path == "/manifest.webmanifest":
            self._send(200, "application/manifest+json", json.dumps(MANIFEST).encode())
        elif self.path in ("/apple-touch-icon.png", "/icon.png", "/favicon.ico"):
            self._send(200, "image/png", ICON)
        else:
            self._send(404, "text/plain", b"not found")


def lan_ip() -> str:
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.connect(("8.8.8.8", 80))
        ip = sock.getsockname()[0]
        sock.close()
        return ip
    except OSError:
        return "127.0.0.1"


def main() -> int:
    global AUTH, ICON, WEB_DIR

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--port", type=int, default=8099)
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--endpoint", default="http://localhost:6176")
    parser.add_argument("--proxy", default=None)
    parser.add_argument("--days", type=int, default=7,
                        help="how far back to ask Apple (max ~7)")
    parser.add_argument("--name", default="beacon")
    parser.add_argument("--keys-file", default=None,
                        help="key ring JSON (default keys/<name>_keys.json)")
    parser.add_argument("--store", default=None)
    parser.add_argument("--poll", type=int, default=15,
                        help="background poll interval in minutes, 0 disables")
    parser.add_argument("--keep-days", type=int, default=365,
                        help="drop history older than this many days, 0 = keep all")
    parser.add_argument("--max-points", type=int, default=20000,
                        help="hard cap on stored points, oldest dropped first (0 = no cap)")
    parser.add_argument("--auth", default=None,
                        help="HTTP basic auth as user:password")
    parser.add_argument("--web-dir", default=None,
                        help="directory with index.html (default scripts/web)")
    args = parser.parse_args()

    if args.auth:
        user, _, password = args.auth.partition(":")
        if not user or not password:
            parser.error("--auth must be user:password")
        AUTH = (user, password)

    if args.web_dir:
        WEB_DIR = pathlib.Path(args.web_dir)

    keys = load_keys(args.name, args.keys_file)

    store = pathlib.Path(args.store) if args.store else (
        ROOT / "keys" / f"{args.name}_history.json"
    )
    history = History(store, args.keep_days, args.max_points)
    ICON = make_icon()

    Handler.keys = keys
    Handler.args = args
    Handler.history = history

    if args.poll > 0:
        def poller():
            while True:
                time.sleep(args.poll * 60)
                try:
                    collect(args, keys, history)
                    print(f"polled: {len(history.snapshot())} points stored", flush=True)
                except Exception as exc:  # noqa: BLE001
                    print(f"poll failed: {exc}", flush=True)

        threading.Thread(target=poller, daemon=True).start()

    server = ThreadingHTTPServer((args.host, args.port), Handler)
    print(f"keys     : {len(keys)} slots (queried together)")
    print(f"source   : {args.proxy or args.endpoint}")
    print(f"history  : {store} ({len(history.snapshot())} points, keep "
          f"{args.keep_days or 'all'} days)")
    print(f"polling  : every {args.poll} min" if args.poll else "polling  : off")
    print(f"auth     : {'yes' if AUTH else 'no'}")
    print(f"PC       : http://localhost:{args.port}")
    if args.host == "0.0.0.0":
        print(f"iPhone   : http://{lan_ip()}:{args.port}   (same Wi-Fi)")
    print("Ctrl+C to stop")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nstopped")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
