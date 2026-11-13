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
from decrypt_reports import decrypt_payload  # noqa: E402

ROOT = pathlib.Path(__file__).resolve().parent.parent
AUTH = None  # (user, password) when --auth is given

PAGE = """<!doctype html>
<html>
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">
<title>BT_Beacon</title>
<meta name="theme-color" content="#1a73e8">
<meta name="apple-mobile-web-app-capable" content="yes">
<meta name="apple-mobile-web-app-status-bar-style" content="default">
<meta name="apple-mobile-web-app-title" content="Beacon">
<link rel="manifest" href="/manifest.webmanifest">
<link rel="apple-touch-icon" href="/apple-touch-icon.png">
<link rel="stylesheet" href="https://unpkg.com/leaflet@1.9.4/dist/leaflet.css">
<style>
  html, body, #map { height: 100%; margin: 0; }
  .panel {
    position: absolute; z-index: 1000; background: rgba(255,255,255,.96);
    border-radius: 8px; box-shadow: 0 2px 8px rgba(0,0,0,.3);
    font: 13px/1.45 system-ui, sans-serif;
  }
  #hud { top: 10px; left: 50px; right: 10px; max-width: 340px; padding: 10px 12px; }
  #hud b { font-size: 15px; }
  #open { display:block; margin:9px 0 4px; padding:11px 12px; background:#1a73e8;
          color:#fff; text-align:center; text-decoration:none; border-radius:6px;
          font-weight:600; font-size:15px; }
  #open.off { background:#9aa0a6; pointer-events:none; }
  #hud a.alt { color:#1a73e8; text-decoration:none; font-size:12px; margin-right:12px; }
  #hud small { color:#555; }
  #hist { top: auto; bottom: 10px; left: 50px; width: 260px; max-height: 42vh;
          display: flex; flex-direction: column; overflow: hidden; }
  #hist h3 { margin: 0; padding: 8px 10px; font-size: 12px; text-transform: uppercase;
             letter-spacing: .04em; color: #555; border-bottom: 1px solid #eee; }
  #list { overflow-y: auto; }
  .row { padding: 7px 10px; border-bottom: 1px solid #f2f2f2; cursor: pointer; }
  .row:hover { background: #f0f6ff; }
  .row .t { font-weight: 600; }
  .row .d { color: #666; font-size: 11px; }
  #hint { display:none; bottom: 10px; right: 10px; max-width: 280px; padding: 12px; }
  #hint button { margin-top: 4px; padding: 6px 12px; }
  .err { color: #b00; }
</style>
</head>
<body>
<div id="map"></div>
<div id="hud" class="panel">
  <b id="count">loading&hellip;</b><br>
  <span id="seen"></span><br>
  <a id="open" class="off" href="#">Open latest in Google Maps</a>
  <a id="apple" class="alt" href="#">Apple Maps</a>
  <a id="copy" class="alt" href="#">Copy coordinates</a>
  <a id="install" class="alt" href="#">Add to Home Screen</a>
  <br><small id="meta"></small>
</div>
<div id="hist" class="panel">
  <h3 id="histtitle">History</h3>
  <div id="list"></div>
</div>
<div id="hint" class="panel">
  <b>Add to Home Screen</b>
  <p id="hinttext" style="margin:8px 0 10px;"></p>
  <button id="hintclose">Got it</button>
</div>
<script src="https://unpkg.com/leaflet@1.9.4/dist/leaflet.js"></script>
<script>
const map = L.map('map').setView([0, 0], 2);
L.tileLayer('https://tile.openstreetmap.org/{z}/{x}/{y}.png', {
  maxZoom: 19, attribution: '&copy; OpenStreetMap'
}).addTo(map);

let layer = L.layerGroup().addTo(map);
let markers = [];
let first = true;

function rowLabel(x) {
  return new Date(x.when).toLocaleDateString([], {month: 'short', day: 'numeric'});
}
function rowTime(x) {
  return new Date(x.when).toLocaleTimeString([], {hour: '2-digit', minute: '2-digit', second: '2-digit'});
}

async function refresh() {
  try {
    const r = await fetch('/api/reports', {cache: 'no-store'});
    const data = await r.json();
    if (data.error) throw new Error(data.error);

    layer.clearLayers();
    markers = [];
    const rs = data.reports;
    const pts = rs.map(x => [x.lat, x.lon]);

    rs.forEach((x, i) => {
      const newest = i === rs.length - 1;
      const m = L.circleMarker([x.lat, x.lon], {
        radius: newest ? 10 : 5,
        color: newest ? '#d00' : '#1a73e8',
        weight: 2, fillOpacity: newest ? 0.95 : 0.5
      }).bindPopup(
        `<b>${new Date(x.when).toLocaleString()}</b><br>` +
        `accuracy ${x.accuracy} m<br>${x.lat.toFixed(6)}, ${x.lon.toFixed(6)}`
      ).addTo(layer);
      markers.push(m);
    });

    if (pts.length > 1) L.polyline(pts, {color: '#1a73e8', weight: 2, opacity: .5}).addTo(layer);
    if (pts.length && first) { map.fitBounds(pts, {padding: [40, 40]}); first = false; }

    document.getElementById('count').textContent = rs.length + ' report(s)';
    const last = rs.length ? rs[rs.length - 1] : null;
    document.getElementById('seen').textContent =
      last ? 'last seen ' + new Date(last.when).toLocaleString() : 'no reports yet';
    document.getElementById('meta').textContent =
      (data.stored_since ? 'since ' + new Date(data.stored_since).toLocaleDateString() : '') +
      (data.keep_days ? ' · keep ' + data.keep_days + 'd' : ' · keep all') +
      ' · updated ' + new Date().toLocaleTimeString();

    const list = document.getElementById('list');
    list.innerHTML = '';
    for (let i = rs.length - 1; i >= 0; i--) {
      const x = rs[i];
      const row = document.createElement('div');
      row.className = 'row';
      row.innerHTML = `<span class="t">${rowTime(x)}</span> ` +
                      `<span class="d">${rowLabel(x)} · ${x.accuracy} m</span>`;
      row.onclick = () => { map.setView([x.lat, x.lon], 17); markers[i] && markers[i].openPopup(); };
      list.appendChild(row);
    }
    document.getElementById('histtitle').textContent = 'History · ' + rs.length;

    const open = document.getElementById('open');
    if (last) {
      const q = last.lat.toFixed(6) + ',' + last.lon.toFixed(6);
      open.href = 'https://www.google.com/maps/search/?api=1&query=' + q;
      open.classList.remove('off');
      document.getElementById('apple').href = 'https://maps.apple.com/?ll=' + q + '&q=Beacon';
      document.getElementById('copy').onclick = () =>
        navigator.clipboard && navigator.clipboard.writeText(q);
    } else {
      open.classList.add('off');
    }
  } catch (e) {
    document.getElementById('count').innerHTML = '<span class="err">' + e.message + '</span>';
  }
}

// --- install / add to home screen ---
let deferredPrompt = null;
window.addEventListener('beforeinstallprompt', e => { e.preventDefault(); deferredPrompt = e; });

const installBtn = document.getElementById('install');
const standalone = window.matchMedia('(display-mode: standalone)').matches || navigator.standalone;
if (standalone) installBtn.style.display = 'none';

installBtn.onclick = async (e) => {
  e.preventDefault();
  if (deferredPrompt) { deferredPrompt.prompt(); deferredPrompt = null; return; }
  const ios = /iphone|ipad|ipod/i.test(navigator.userAgent);
  document.getElementById('hinttext').textContent = ios
    ? 'In Safari tap the Share button (square with an arrow), then "Add to Home Screen". The icon opens this page and fetches the latest fix.'
    : 'Open the browser menu and choose "Install app" or "Add to Home screen".';
  document.getElementById('hint').style.display = 'block';
};
document.getElementById('hintclose').onclick = () =>
  document.getElementById('hint').style.display = 'none';

refresh();
setInterval(refresh, 30000);
</script>
</body>
</html>
"""

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


def key_hash_b64(private_key) -> str:
    adv = private_key.public_key().public_numbers().x.to_bytes(28, "big")
    return base64.b64encode(hashlib.sha256(adv).digest()).decode()


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

    def __init__(self, path: pathlib.Path, keep_days: int = 0):
        self.path = path
        self.keep_days = keep_days
        self.lock = threading.Lock()
        self.points: list[dict] = []
        if path.exists():
            try:
                self.points = json.loads(path.read_text()).get("points", [])
            except (ValueError, OSError):
                self.points = []

    def _trim(self) -> None:
        if not self.keep_days:
            return
        cutoff = (datetime.now(timezone.utc) - timedelta(days=self.keep_days)).isoformat()
        self.points = [p for p in self.points if p["when"] >= cutoff]

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


def fetch_reports(args, key_hash: str) -> list[dict]:
    if args.proxy:
        url = args.proxy
        body = {"search": [{"ids": [key_hash]}]}
    else:
        url = args.endpoint.rstrip("/") + "/"
        body = {"ids": [key_hash], "days": args.days}

    request = urllib.request.Request(
        url,
        data=json.dumps(body).encode(),
        headers={"Content-Type": "application/json"},
    )
    with urllib.request.urlopen(request, timeout=120) as response:
        return json.load(response).get("results", [])


def collect(args, private_key, history: History) -> None:
    try:
        raw = fetch_reports(args, key_hash_b64(private_key))
    except Exception as exc:  # noqa: BLE001
        raise RuntimeError(f"fetch failed: {exc}") from exc

    fresh = []
    for report in raw:
        try:
            point = decrypt_payload(report["payload"], private_key)
        except Exception:  # noqa: BLE001
            continue
        point["id"] = hashlib.sha1(report["payload"].encode()).hexdigest()
        fresh.append(point)

    history.merge(fresh)


def build_payload(args, private_key, history: History) -> dict:
    try:
        collect(args, private_key, history)
    except RuntimeError as exc:
        if not history.snapshot():
            return {"error": str(exc), "keep_days": args.keep_days}
    points = history.snapshot()
    return {
        "count": len(points),
        "reports": points,
        "stored_since": points[0]["when"] if points else None,
        "keep_days": args.keep_days,
    }


class Handler(BaseHTTPRequestHandler):
    private_key = None
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
            payload = build_payload(self.args, self.private_key, self.history)
            self._send(200, "application/json", json.dumps(payload).encode())
        elif self.path in ("/", "/index.html"):
            self._send(200, "text/html; charset=utf-8", PAGE.encode())
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
    global AUTH, ICON

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--port", type=int, default=8099)
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--endpoint", default="http://localhost:6176")
    parser.add_argument("--proxy", default=None)
    parser.add_argument("--days", type=int, default=7,
                        help="how far back to ask Apple (max ~7)")
    parser.add_argument("--name", default="beacon")
    parser.add_argument("--key-file", default=None)
    parser.add_argument("--store", default=None)
    parser.add_argument("--poll", type=int, default=15,
                        help="background poll interval in minutes, 0 disables")
    parser.add_argument("--keep-days", type=int, default=365,
                        help="drop history older than this many days, 0 = keep all")
    parser.add_argument("--auth", default=None,
                        help="HTTP basic auth as user:password")
    args = parser.parse_args()

    if args.auth:
        user, _, password = args.auth.partition(":")
        if not user or not password:
            parser.error("--auth must be user:password")
        AUTH = (user, password)

    key_file = pathlib.Path(args.key_file) if args.key_file else (
        ROOT / "keys" / f"{args.name}.priv.hex"
    )
    private_key = ec.derive_private_key(
        int.from_bytes(bytes.fromhex(key_file.read_text().strip()), "big"),
        ec.SECP224R1(),
    )

    store = pathlib.Path(args.store) if args.store else (
        ROOT / "keys" / f"{args.name}_history.json"
    )
    history = History(store, args.keep_days)
    ICON = make_icon()

    Handler.private_key = private_key
    Handler.args = args
    Handler.history = history

    if args.poll > 0:
        def poller():
            while True:
                time.sleep(args.poll * 60)
                try:
                    collect(args, private_key, history)
                    print(f"polled: {len(history.snapshot())} points stored", flush=True)
                except Exception as exc:  # noqa: BLE001
                    print(f"poll failed: {exc}", flush=True)

        threading.Thread(target=poller, daemon=True).start()

    server = ThreadingHTTPServer((args.host, args.port), Handler)
    print(f"key hash : {key_hash_b64(private_key)}")
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
