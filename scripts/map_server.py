#!/usr/bin/env python3
"""
Multi-tag / multi-user dashboard for the BT_Beacon tags.

- every ``keys/<name>_keys.json`` becomes a tag
- users live in SQLite, authenticated with HTTP basic auth
- a user only sees the tags granted to them; admins see everything and can
  manage users, tags and grants from /admin

The Apple session is shared: report fetching is done once for all tags with a
single account (Apple serves any authenticated client the reports for any hash).
"""

import argparse
import base64
import hashlib
import hmac
import json
import os
import pathlib
import socket
import sqlite3
import struct
import sys
import threading
import time
import urllib.request
import zlib
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs

from cryptography.hazmat.primitives.asymmetric import ec

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from decrypt_reports import decrypt_payload, load_keys  # noqa: E402

ROOT = pathlib.Path(__file__).resolve().parent.parent
WEB_DIR = ROOT / "scripts" / "web"
STATE = {"last_ok": None, "last_error": None, "last_fetch": 0.0, "fetching": False}

PBKDF2_ROUNDS = 120_000


# --------------------------------------------------------------------------- #
# helpers
# --------------------------------------------------------------------------- #
def hash_password(password: str) -> str:
    salt = os.urandom(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, PBKDF2_ROUNDS)
    return f"{salt.hex()}${PBKDF2_ROUNDS}${digest.hex()}"


def verify_password(password: str, stored: str) -> bool:
    try:
        salt_hex, rounds, digest_hex = stored.split("$")
        digest = hashlib.pbkdf2_hmac("sha256", password.encode(),
                                     bytes.fromhex(salt_hex), int(rounds))
    except (ValueError, TypeError):
        return False
    return hmac.compare_digest(digest.hex(), digest_hex)


def make_icon(size: int = 180) -> bytes:
    centre = (size - 1) / 2
    outer = size * 0.40
    inner = size * 0.15

    raw = bytearray()
    for y in range(size):
        raw.append(0)
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


# --------------------------------------------------------------------------- #
# storage
# --------------------------------------------------------------------------- #
class Store:
    def __init__(self, path: pathlib.Path, keep_days: int = 0, max_points: int = 0,
                 legacy_json: pathlib.Path | None = None):
        self.path = path
        self.keep_days = keep_days
        self.max_points = max_points
        self.lock = threading.Lock()
        path.parent.mkdir(parents=True, exist_ok=True)
        self.db = sqlite3.connect(str(path), check_same_thread=False)
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.execute("PRAGMA synchronous=NORMAL")
        self.db.execute("PRAGMA foreign_keys=ON")
        self.db.executescript("""
            CREATE TABLE IF NOT EXISTS tags (
                id   INTEGER PRIMARY KEY,
                name TEXT UNIQUE NOT NULL
            );
            CREATE TABLE IF NOT EXISTS tag_keys (
                tag_id   INTEGER NOT NULL REFERENCES tags(id) ON DELETE CASCADE,
                hash_b64 TEXT NOT NULL,
                PRIMARY KEY (tag_id, hash_b64)
            );
            CREATE TABLE IF NOT EXISTS users (
                id       INTEGER PRIMARY KEY,
                username TEXT UNIQUE NOT NULL,
                pw_hash  TEXT NOT NULL,
                is_admin INTEGER NOT NULL DEFAULT 0
            );
            CREATE TABLE IF NOT EXISTS access (
                user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                tag_id  INTEGER NOT NULL REFERENCES tags(id) ON DELETE CASCADE,
                PRIMARY KEY (user_id, tag_id)
            );
            CREATE TABLE IF NOT EXISTS points (
                id         TEXT PRIMARY KEY,
                tag_id     INTEGER NOT NULL DEFAULT 0,
                ts         INTEGER NOT NULL,
                when_iso   TEXT    NOT NULL,
                lat        REAL    NOT NULL,
                lon        REAL    NOT NULL,
                accuracy   INTEGER,
                status     INTEGER,
                confidence INTEGER
            );
        """)
        # older databases predate tag_id: migrate before creating its index
        cols = {row[1] for row in self.db.execute("PRAGMA table_info(points)")}
        if "tag_id" not in cols:
            self.db.execute("ALTER TABLE points ADD COLUMN tag_id INTEGER NOT NULL DEFAULT 0")
        self.db.executescript("""
            CREATE INDEX IF NOT EXISTS points_ts ON points(ts);
            CREATE INDEX IF NOT EXISTS points_tag_ts ON points(tag_id, ts);
        """)
        self.db.commit()

        if legacy_json and legacy_json.exists():
            self._import_json(legacy_json)

    # ---- migration --------------------------------------------------------
    def _import_json(self, path: pathlib.Path) -> None:
        try:
            data = json.loads(path.read_text()).get("points", [])
        except (ValueError, OSError) as exc:
            print(f"could not import {path.name}: {exc}", flush=True)
            return
        if not data:
            path.unlink(missing_ok=True)
            return
        with self.lock:
            for p in data:
                self.db.execute(
                    "INSERT OR IGNORE INTO points"
                    "(id, ts, when_iso, lat, lon, accuracy, status, confidence)"
                    " VALUES (?,?,?,?,?,?,?,?)",
                    (p["id"], int(_epoch(p["when"])), p["when"], p["lat"], p["lon"],
                     p.get("accuracy"), p.get("status"), p.get("confidence")))
            self.db.commit()
        path.rename(path.with_suffix(".json.imported"))
        print(f"imported {len(data)} points from {path.name}", flush=True)

    # ---- tags -------------------------------------------------------------
    def sync_tags(self, rings: dict) -> None:
        """rings: {tag_name: {hash_b64: private_key}}"""
        with self.lock:
            for name, hashes in rings.items():
                row = self.db.execute("SELECT id FROM tags WHERE name=?", (name,)).fetchone()
                if row:
                    tag_id = row[0]
                else:
                    cur = self.db.execute("INSERT INTO tags(name) VALUES (?)", (name,))
                    tag_id = cur.lastrowid
                for h in hashes:
                    self.db.execute(
                        "INSERT OR IGNORE INTO tag_keys(tag_id, hash_b64) VALUES (?,?)",
                        (tag_id, h))
            # attach points created before tagging to the oldest tag (the
            # original ring); newer points always carry their tag_id
            first = self.db.execute("SELECT id FROM tags ORDER BY id LIMIT 1").fetchone()
            if first:
                self.db.execute("UPDATE points SET tag_id=? WHERE tag_id=0", (first[0],))
            self.db.commit()

    def all_tags(self) -> list[dict]:
        rows = self.db.execute("""
            SELECT t.id, t.name,
                   (SELECT count(*) FROM points p WHERE p.tag_id = t.id) AS n,
                   (SELECT max(when_iso) FROM points p WHERE p.tag_id = t.id) AS last
            FROM tags t ORDER BY t.name""").fetchall()
        return [{"id": r[0], "name": r[1], "points": r[2], "last_seen": r[3]} for r in rows]

    def tags_for(self, user: dict | None) -> list[dict]:
        tags = self.all_tags()
        if user is None or user["is_admin"]:
            return tags
        allowed = {r[0] for r in self.db.execute(
            "SELECT tag_id FROM access WHERE user_id=?", (user["id"],))}
        return [t for t in tags if t["id"] in allowed]

    def tag_hashes(self) -> dict:
        """tag_id -> set(hash_b64)"""
        out: dict[int, set] = {}
        for tag_id, h in self.db.execute("SELECT tag_id, hash_b64 FROM tag_keys"):
            out.setdefault(tag_id, set()).add(h)
        return out

    # ---- users ------------------------------------------------------------
    def user_count(self) -> int:
        return self.db.execute("SELECT count(*) FROM users").fetchone()[0]

    def upsert_user(self, username: str, password: str | None, is_admin: bool) -> int:
        row = self.db.execute("SELECT id FROM users WHERE username=?", (username,)).fetchone()
        with self.lock:
            if row:
                user_id = row[0]
                if password:
                    self.db.execute("UPDATE users SET pw_hash=?, is_admin=? WHERE id=?",
                                    (hash_password(password), 1 if is_admin else 0, user_id))
                else:
                    self.db.execute("UPDATE users SET is_admin=? WHERE id=?",
                                    (1 if is_admin else 0, user_id))
            else:
                cur = self.db.execute(
                    "INSERT INTO users(username, pw_hash, is_admin) VALUES (?,?,?)",
                    (username, hash_password(password or os.urandom(12).hex()),
                     1 if is_admin else 0))
                user_id = cur.lastrowid
            self.db.commit()
        return user_id

    def delete_user(self, user_id: int) -> None:
        with self.lock:
            self.db.execute("DELETE FROM users WHERE id=?", (user_id,))
            self.db.commit()

    def authenticate(self, username: str, password: str) -> dict | None:
        row = self.db.execute(
            "SELECT id, username, pw_hash, is_admin FROM users WHERE username=?",
            (username,)).fetchone()
        if not row or not verify_password(password, row[2]):
            return None
        return {"id": row[0], "username": row[1], "is_admin": bool(row[3])}

    def users(self) -> list[dict]:
        out = []
        for r in self.db.execute("SELECT id, username, is_admin FROM users ORDER BY username"):
            tags = [x[0] for x in self.db.execute(
                "SELECT tag_id FROM access WHERE user_id=?", (r[0],))]
            out.append({"id": r[0], "username": r[1], "is_admin": bool(r[2]), "tag_ids": tags})
        return out

    def grant(self, user_id: int, tag_id: int, allow: bool) -> None:
        with self.lock:
            if allow:
                self.db.execute("INSERT OR IGNORE INTO access(user_id, tag_id) VALUES (?,?)",
                                (user_id, tag_id))
            else:
                self.db.execute("DELETE FROM access WHERE user_id=? AND tag_id=?",
                                (user_id, tag_id))
            self.db.commit()

    # ---- points -----------------------------------------------------------
    def merge(self, tag_id: int, new_points: list[dict]) -> None:
        with self.lock:
            changed = False
            for p in new_points:
                cur = self.db.execute(
                    "INSERT OR IGNORE INTO points"
                    "(id, tag_id, ts, when_iso, lat, lon, accuracy, status, confidence)"
                    " VALUES (?,?,?,?,?,?,?,?,?)",
                    (p["id"], tag_id, int(_epoch(p["when"])), p["when"], p["lat"], p["lon"],
                     p.get("accuracy"), p.get("status"), p.get("confidence")))
                changed = changed or cur.rowcount > 0
            if changed:
                self._trim()
                self.db.commit()

    def _trim(self) -> None:
        if self.keep_days:
            cutoff = int((datetime.now(timezone.utc)
                          - timedelta(days=self.keep_days)).timestamp())
            self.db.execute("DELETE FROM points WHERE ts < ?", (cutoff,))
        if self.max_points:
            self.db.execute(
                "DELETE FROM points WHERE id NOT IN "
                "(SELECT id FROM points ORDER BY ts DESC LIMIT ?)", (self.max_points,))

    def count(self, tag_ids=None) -> int:
        if tag_ids is None:
            return self.db.execute("SELECT count(*) FROM points").fetchone()[0]
        if not tag_ids:
            return 0
        q = ",".join("?" * len(tag_ids))
        return self.db.execute(f"SELECT count(*) FROM points WHERE tag_id IN ({q})",
                               list(tag_ids)).fetchone()[0]

    def first_when(self, tag_ids=None):
        if tag_ids is None:
            row = self.db.execute("SELECT when_iso FROM points ORDER BY ts LIMIT 1").fetchone()
        else:
            if not tag_ids:
                return None
            q = ",".join("?" * len(tag_ids))
            row = self.db.execute(
                f"SELECT when_iso FROM points WHERE tag_id IN ({q}) ORDER BY ts LIMIT 1",
                list(tag_ids)).fetchone()
        return row[0] if row else None

    @staticmethod
    def _row(row) -> dict:
        return {"id": row[0], "tag_id": row[1], "when": row[2], "lat": row[3],
                "lon": row[4], "accuracy": row[5], "status": row[6], "confidence": row[7]}

    def query(self, tag_ids, from_ts=None, to_ts=None, days: int = 0) -> list[dict]:
        where, params = [], []
        if tag_ids is not None:
            if not tag_ids:
                return []
            where.append("tag_id IN (" + ",".join("?" * len(tag_ids)) + ")")
            params.extend(tag_ids)
        if from_ts is not None:
            where.append("ts >= ?")
            params.append(int(from_ts))
        if to_ts is not None:
            where.append("ts < ?")
            params.append(int(to_ts))
        if days:
            cutoff = (datetime.now(timezone.utc) - timedelta(days=days)).timestamp()
            where.append("ts >= ?")
            params.append(int(cutoff))

        sql = ("SELECT id, tag_id, when_iso, lat, lon, accuracy, status, confidence"
               " FROM points")
        if where:
            sql += " WHERE " + " AND ".join(where)
        sql += " ORDER BY ts"
        return [self._row(r) for r in self.db.execute(sql, params).fetchall()]

    def query_ranges(self, tag_ids, ranges) -> list[dict]:
        """Reports inside any of the [start, end) UTC ranges (multi-day select)."""
        where, params = [], []
        if tag_ids is not None:
            if not tag_ids:
                return []
            where.append("tag_id IN (" + ",".join("?" * len(tag_ids)) + ")")
            params.extend(tag_ids)
        if ranges:
            where.append("(" + " OR ".join(["(ts >= ? AND ts < ?)"] * len(ranges)) + ")")
            for start, end in ranges:
                params.extend([int(start), int(end)])
        sql = ("SELECT id, tag_id, when_iso, lat, lon, accuracy, status, confidence"
               " FROM points")
        if where:
            sql += " WHERE " + " AND ".join(where)
        sql += " ORDER BY ts"
        return [self._row(r) for r in self.db.execute(sql, params).fetchall()]

    def summary(self, tag_ids, tz_offset_min: int) -> dict:
        if tag_ids is not None and not tag_ids:
            return {}
        q = ""
        params = [tz_offset_min * 60]
        if tag_ids is not None:
            q = " WHERE tag_id IN (" + ",".join("?" * len(tag_ids)) + ")"
            params.extend(tag_ids)
        rows = self.db.execute(
            "SELECT date(ts - ?, 'unixepoch') AS d, count(*) FROM points"
            + q + " GROUP BY d", params).fetchall()
        return {r[0]: r[1] for r in rows}


def _epoch(iso: str) -> float:
    return datetime.fromisoformat(iso.replace("Z", "+00:00")).timestamp()


# --------------------------------------------------------------------------- #
# fetching
# --------------------------------------------------------------------------- #
def _post_ids(url: str, ids: list[str], days: int) -> list[dict]:
    request = urllib.request.Request(
        url, data=json.dumps({"ids": ids, "days": days}).encode(),
        headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(request, timeout=120) as response:
        return json.load(response).get("results", [])


def fetch_reports(args, hashes: list[str]) -> list[dict]:
    if args.proxy:
        url, body = args.proxy, {"search": [{"ids": hashes}]}
        request = urllib.request.Request(
            url, data=json.dumps(body).encode(),
            headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(request, timeout=120) as response:
            return json.load(response).get("results", [])

    # Apple's fetch service only answers the *tail* of a multi-id request
    # (observed 2026-11-17: a 192-id call returned reports for the last id and
    # silently ignored the other 191, so both tags effectively stopped being
    # fetched). One id per request is the only shape that reliably returns a
    # slot's reports. The endpoint server is single-threaded, so the sweep takes
    # roughly a minute per tag pair; keep --poll well above that.
    url = args.endpoint.rstrip("/") + "/"
    results: list[dict] = []
    state = {"ok": 0}

    def one(h: str) -> list[dict]:
        try:
            found = _post_ids(url, [h], args.days)
            state["ok"] += 1
            return found
        except Exception as exc:  # noqa: BLE001
            print(f"fetch failed for {h[:8]}: {exc}", flush=True)
            return []

    workers = max(1, min(args.fetch_workers, 8))
    with ThreadPoolExecutor(max_workers=workers) as pool:
        for chunk in pool.map(one, hashes):
            results.extend(chunk)

    if hashes and state["ok"] == 0:
        raise RuntimeError("every per-id fetch failed")
    return results


def collect(args, store: Store, rings: dict, tag_ids: dict) -> None:
    """Fetch every tag's hashes, decrypt per tag, store."""
    all_hashes = [h for ring in rings.values() for h in ring]
    try:
        raw = fetch_reports(args, all_hashes)
    except Exception as exc:  # noqa: BLE001
        STATE["last_error"] = f"fetch failed: {exc}"
        raise RuntimeError(STATE["last_error"]) from exc

    hash_to_tag, hash_to_key = {}, {}
    for name, ring in rings.items():
        tid = tag_ids.get(name)
        if tid is None:
            continue
        for h, key in ring.items():
            hash_to_tag[h] = tid
            hash_to_key[h] = key

    fresh: dict[int, list[dict]] = {}
    for report in raw:
        payload = report["payload"]
        tag_id = hash_to_tag.get(report.get("id"))
        if tag_id is None:
            continue
        key = hash_to_key.get(report.get("id"))
        try:
            point = decrypt_payload(payload, key)
        except Exception:  # noqa: BLE001
            continue
        point["id"] = hashlib.sha1(payload.encode()).hexdigest()
        fresh.setdefault(tag_id, []).append(point)

    for tag_id, points in fresh.items():
        store.merge(tag_id, points)

    STATE["last_ok"] = datetime.now(timezone.utc).isoformat(timespec="seconds")
    STATE["last_error"] = None


def _collect_guarded(args, store: Store, rings: dict, tag_ids: dict) -> str | None:
    """Run one sweep, but never two at a time."""
    if STATE["fetching"]:
        return STATE["last_error"]
    STATE["fetching"] = True
    try:
        collect(args, store, rings, tag_ids)
        return None
    except RuntimeError as exc:
        return str(exc)
    finally:
        STATE["fetching"] = False


def maybe_refresh(args, store: Store, rings: dict, tag_ids: dict, force: bool) -> str | None:
    if not force and time.time() - STATE["last_fetch"] < args.refresh_seconds:
        return STATE["last_error"]

    # A sweep is one request per hash, so it takes about a minute. Never block
    # an HTTP response on it: refresh in the background and serve stored data.
    if not force:
        STATE["last_fetch"] = time.time()

        def run():
            error = _collect_guarded(args, store, rings, tag_ids)
            if error:
                print(f"background fetch failed: {error}", flush=True)

        threading.Thread(target=run, daemon=True).start()
        return STATE["last_error"]

    STATE["last_fetch"] = time.time()
    return _collect_guarded(args, store, rings, tag_ids)


# --------------------------------------------------------------------------- #
# HTTP
# --------------------------------------------------------------------------- #
class Handler(BaseHTTPRequestHandler):
    store: Store = None
    args = None
    rings: dict = None
    tag_ids: dict = None
    keys_dir: pathlib.Path = None
    icon: bytes = None

    def log_message(self, fmt, *a):
        pass

    # ---- auth -------------------------------------------------------------
    def _user(self) -> dict | None:
        if self.store.user_count() == 0:
            return {"id": 0, "username": "anonymous", "is_admin": True}
        header = self.headers.get("Authorization", "")
        if not header.startswith("Basic "):
            return None
        try:
            username, _, password = base64.b64decode(header[6:]).decode().partition(":")
        except Exception:  # noqa: BLE001
            return None
        return self.store.authenticate(username, password)

    # ---- responses --------------------------------------------------------
    def _send(self, code, content_type, body: bytes):
        self.send_response(code)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        if code == 401:
            self.send_header("WWW-Authenticate", 'Basic realm="beacon"')
        self.end_headers()
        self.wfile.write(body)

    def _json(self, payload, code=200):
        self._send(code, "application/json", json.dumps(payload).encode())

    def _file(self, name: str, content_type: str):
        try:
            body = (pathlib.Path(WEB_DIR) / name).read_bytes()
            self._send(200, content_type, body)
        except OSError as exc:  # noqa: BLE001
            self._send(500, "text/plain", f"cannot read {name}: {exc}".encode())

    def _tag_scope(self, user: dict, query: dict):
        tags = self.store.tags_for(user)
        ids = {t["id"] for t in tags}
        wanted = (query.get("tag") or [""])[0]
        if wanted.isdigit():
            tid = int(wanted)
            return [tid] if tid in ids else []
        return None if user["is_admin"] else sorted(ids)

    def _read_json(self) -> dict:
        length = int(self.headers.get("Content-Length") or 0)
        if not length:
            return {}
        try:
            return json.loads(self.rfile.read(length))
        except ValueError:
            return {}

    # ---- routes -----------------------------------------------------------
    def do_GET(self):
        user = self._user()
        if user is None:
            self._send(401, "text/plain", b"auth required")
            return

        path, _, raw = self.path.partition("?")
        query = parse_qs(raw)

        if path == "/":
            self._file("index.html", "text/html; charset=utf-8")
        elif path == "/admin":
            if not user["is_admin"]:
                self._send(403, "text/plain", b"admin only")
                return
            self._file("admin.html", "text/html; charset=utf-8")
        elif path == "/manifest.webmanifest":
            self._json({
                "name": "BT_Beacon", "short_name": "Beacon", "start_url": "./",
                "scope": "./", "display": "standalone",
                "background_color": "#1a73e8", "theme_color": "#1a73e8",
                "icons": [{"src": "apple-touch-icon.png", "sizes": "180x180",
                           "type": "image/png"}],
            })
        elif path in ("/apple-touch-icon.png", "/icon.png", "/favicon.ico"):
            self._send(200, "image/png", self.icon)
        elif path == "/api/tags":
            self._json({"tags": self.store.tags_for(user)})
        elif path == "/api/reports":
            self._reports(user, query)
        elif path == "/api/summary":
            self._summary(user, query)
        elif path == "/api/admin/overview":
            if not user["is_admin"]:
                self._send(403, "text/plain", b"admin only")
                return
            keys_dir = self.keys_dir
            self._json({
                "users": self.store.users(),
                "tags": self.store.all_tags(),
                "keys_dir": str(keys_dir),
                "ring_files": sorted(p.name for p in keys_dir.glob("*_keys.json")),
                "loaded_rings": {n: len(r) for n, r in self.rings.items()},
            })
        else:
            self._send(404, "text/plain", b"not found")

    def do_POST(self):
        user = self._user()
        if user is None:
            self._send(401, "text/plain", b"auth required")
            return
        if not user["is_admin"]:
            self._send(403, "text/plain", b"admin only")
            return

        path, _, _ = self.path.partition("?")
        body = self._read_json()

        if path == "/api/admin/user":
            username = (body.get("username") or "").strip()
            if not username:
                self._json({"error": "username required"}, 400)
                return
            uid = self.store.upsert_user(username, body.get("password") or None,
                                         bool(body.get("is_admin")))
            self._json({"id": uid, "users": self.store.users()})
        elif path == "/api/admin/user/delete":
            try:
                self.store.delete_user(int(body.get("id")))
            except (TypeError, ValueError):
                self._json({"error": "id required"}, 400)
                return
            self._json({"users": self.store.users()})
        elif path == "/api/admin/access":
            try:
                self.store.grant(int(body["user_id"]), int(body["tag_id"]),
                                 bool(body.get("grant")))
            except (KeyError, TypeError, ValueError):
                self._json({"error": "user_id and tag_id required"}, 400)
                return
            self._json({"users": self.store.users()})
        else:
            self._send(404, "text/plain", b"not found")

    # ---- api --------------------------------------------------------------
    def _reports(self, user, query):
        scope = self._tag_scope(user, query)
        error = maybe_refresh(self.args, self.store, self.rings, self.tag_ids,
                              bool(query.get("force")))

        frm = (query.get("from") or [None])[0]
        to = (query.get("to") or [None])[0]
        from_ts = _epoch(frm) if frm else None
        to_ts = _epoch(to) if to else None
        days = 0 if (from_ts is not None or to_ts is not None) else int(
            (query.get("days") or [self.args.ui_days])[0] or 0)

        # Multi-day selection: comma-separated local dates, converted to UTC
        # windows with the client's timezone offset (JS getTimezoneOffset()).
        dates = (query.get("dates") or [None])[0]
        if dates:
            try:
                tz_offset = int((query.get("tz") or ["0"])[0] or 0)
            except ValueError:
                tz_offset = 0
            ranges = []
            for key in dates.split(","):
                key = key.strip()
                try:
                    day = datetime.strptime(key, "%Y-%m-%d").replace(tzinfo=timezone.utc)
                except ValueError:
                    continue
                start = day.timestamp() + tz_offset * 60
                ranges.append((start, start + 86400))
            points = self.store.query_ranges(scope, ranges) if ranges else []
        else:
            points = self.store.query(scope, from_ts, to_ts, days)
        self._json({
            "count": len(points),
            "total": self.store.count(scope),
            "reports": points,
            "stored_since": self.store.first_when(scope),
            "keep_days": self.args.keep_days,
            "max_points": self.args.max_points,
            "keys": sum(len(r) for r in self.rings.values()),
            "tags": len(self.rings),            "api": 2,
            "error": error,
            "last_ok": STATE["last_ok"],
        })

    def _summary(self, user, query):
        scope = self._tag_scope(user, query)
        try:
            tz_offset = int((query.get("tz") or ["0"])[0])
        except ValueError:
            tz_offset = 0
        self._json({
            "count": self.store.count(scope),
            "days": self.store.summary(scope, tz_offset),
            "stored_since": self.store.first_when(scope),
            "keep_days": self.args.keep_days,
            "max_points": self.args.max_points,
            "ui_days": self.args.ui_days,
            "keys": sum(len(r) for r in self.rings.values()),
            "tags": self.store.tags_for(user),
            "admin": user["is_admin"],
            "api": 2,
            "error": STATE["last_error"],
            "last_ok": STATE["last_ok"],
        })


# --------------------------------------------------------------------------- #
# main
# --------------------------------------------------------------------------- #
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
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--port", type=int, default=8099)
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--endpoint", default="http://localhost:6176")
    parser.add_argument("--proxy", default=None)
    parser.add_argument("--days", type=int, default=7)
    parser.add_argument("--keys-dir", default=None,
                        help="directory of <name>_keys.json rings (default keys/)")
    parser.add_argument("--store", default=None, help="history sqlite path")
    parser.add_argument("--poll", type=int, default=15)
    parser.add_argument("--keep-days", type=int, default=365)
    parser.add_argument("--max-points", type=int, default=20000)
    parser.add_argument("--ui-days", type=int, default=7)
    parser.add_argument("--refresh-seconds", type=int, default=120)
    parser.add_argument("--fetch-workers", type=int, default=4,
                        help="parallel per-id requests while fetching reports")
    parser.add_argument("--auth", default=None,
                        help="bootstrap admin as user:password (created/updated at start)")
    parser.add_argument("--web-dir", default=None)
    args = parser.parse_args()

    if args.web_dir:
        globals()["WEB_DIR"] = pathlib.Path(args.web_dir)

    keys_dir = pathlib.Path(args.keys_dir) if args.keys_dir else ROOT / "keys"
    rings = {}
    for path in sorted(keys_dir.glob("*_keys.json")):
        name = path.name[:-len("_keys.json")]
        rings[name] = load_keys(name, str(path))
    if not rings:
        print(f"!! no <name>_keys.json in {keys_dir}", flush=True)
        return 1

    store_path = pathlib.Path(args.store) if args.store else (
        ROOT / "keys" / "beacon_history.db")
    store = Store(store_path, args.keep_days, args.max_points,
                  store_path.with_suffix(".json"))
    store.sync_tags(rings)
    tag_ids = {t["name"]: t["id"] for t in store.all_tags() if t["name"] in rings}

    if args.auth:
        username, _, password = args.auth.partition(":")
        if username and password:
            store.upsert_user(username, password, True)
    if store.user_count() == 0:
        print("!! no users configured - dashboard is OPEN (use --auth user:pass)",
              flush=True)

    Handler.store = store
    Handler.args = args
    Handler.rings = rings
    Handler.tag_ids = tag_ids
    Handler.keys_dir = keys_dir
    Handler.icon = make_icon()

    if args.poll > 0:
        def poller():
            while True:
                error = _collect_guarded(args, store, rings, tag_ids)
                if error:
                    print(f"poll failed: {error}", flush=True)
                else:
                    print(f"polled: {store.count()} points", flush=True)
                time.sleep(args.poll * 60)

        threading.Thread(target=poller, daemon=True).start()

    server = ThreadingHTTPServer((args.host, args.port), Handler)
    print(f"tags     : {', '.join(f'{n} ({len(r)} keys)' for n, r in rings.items())}")
    print(f"source   : {args.proxy or args.endpoint}")
    print(f"history  : {store_path} ({store.count()} points)")
    print(f"users    : {store.user_count()}")
    print(f"polling  : every {args.poll} min" if args.poll else "polling  : off")
    print(f"PC       : http://localhost:{args.port}")
    if args.host == "0.0.0.0":
        print(f"LAN      : http://{lan_ip()}:{args.port}")
    print("Ctrl+C to stop")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nstopped")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
