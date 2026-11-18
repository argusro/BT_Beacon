# BT_Beacon

A working **Apple Find My (Offline Finding) beacon** on a Seeed Studio
**XIAO ESP32-C3**, plus a local stack that retrieves and decrypts the location
reports iPhones file for it.

**Status: end-to-end verified 2026-11-13.** Beacon broadcasting → iPhone files
encrypted report → Apple stores it → we authenticate, fetch and decrypt real
coordinates.

## Hardware

| Item | Value |
| --- | --- |
| Board | Seeed Studio XIAO ESP32-C3 (ESP32-C3, RISC-V @ 160 MHz) |
| Flash | 4 MB |
| Port | `COM9` — native USB Serial/JTAG (`VID 303A / PID 1001`) |
| Antenna | U.FL external antenna — **must be attached**, BLE range is tiny without it |

The board has **no built-in user LED** (only a charge indicator). An external LED
on `D10` through ~220 Ω is optional and blinks at 1 Hz.

### Power

The `5V` pin **is VBUS** — Seeed's pin map lists it as `5V | VBUS`, and there is
no diode between it and the USB connector. That has two consequences:

- Feeding it from a converter while USB is plugged in puts the converter in
  parallel with the host's 5 V rail. Put a Schottky (1N5819 / SS34) between the
  converter output and the `5V` pin, **anode on the converter side**, otherwise
  a converter trimmed above 5 V pushes current back into the PC.
- While USB is plugged in you cannot tell which supply is running the board.
  Use a data-only cable (TX/RX/GND, no VBUS) if you want serial while testing a
  battery, and unplug it entirely before drawing conclusions.

Tested arrangement: a 3S LiPo (11.1–12.6 V) through an MP1584 buck set to 5.0 V,
into the `5V` pin. That is also the car install: 12 V → buck → diode → `5V`.
A 1S LiPo on the `BAT` pads is the alternative (onboard charger, leave the `5V`
pin unconnected). At roughly 10–15 mA from the pack, a 1000 mAh 3S lasts days.

## Quick start

```powershell
python scripts/keygen.py                 # 96 rotating keys -> src/beacon_keys.h + keys/
pio run -t upload                        # build + flash
pio device monitor                       # serial log
```

Expected serial output:

```
=========================================
 BT_Beacon - Apple Find My emulation
=========================================
boot #7   reset reason: power-on (1)
watchdog restarts so far: 0
chip        : ESP32-C3 rev 4
keys        : 96, rotating every 900s
start slot  : 23
BLE address : de 0a 24 e6 00 aa
adv frame   : 1e ff 4c 00 12 19 00 d8 2a 0c 3b 0d 3e 7e 17 b1 f9 8d 34 44 85 f5 d8 d0 cc 10 3b 52 35 00 00
-----------------------------------------
advertising as a Find My accessory
[    30s] beaconing        key 23/96  boot #7  heap=249416
[   300s] re-arming advertising
```

Verify on the air (uses `.venv` with `bleak`, see Tooling):

```powershell
.\.venv\Scripts\python.exe scripts\ble_scan.py 12
```

## How the beacon works

### The advertising frame

31 bytes — the entire legacy BLE advertising payload. There is no flags AD
structure, exactly like a real AirTag.

| Bytes | Value | Meaning |
| --- | --- | --- |
| `[0]` | `0x1e` | AD length: 30 bytes follow |
| `[1]` | `0xff` | AD type: manufacturer specific data |
| `[2..3]` | `4c 00` | Apple company ID `0x004C` (little endian) |
| `[4]` | `0x12` | Apple type: Find My / Offline Finding |
| `[5]` | `0x19` | payload length: 25 |
| `[6]` | `0x00` | status (battery/hint) |
| `[7..28]` | key `[6..27]` | last 22 bytes of the advertising key |
| `[29]` | key `[0] >> 6` | top two bits of key byte 0 |
| `[30]` | `0x00` | hint |

### The other 6 key bytes live in the BLE address

```
addr[0] = key[0] | 0xC0    # top two bits 0b11 = static random address
addr[1..5] = key[1..5]
```

P-224 is the right curve because its X coordinate is exactly 28 bytes — the
largest EC key that fits across one advertisement plus the address.

### Key rotation

Real AirTags rotate their advertising key every ~15 minutes. This firmware does
the same using a pre-generated ring of independent key pairs:

| | |
| --- | --- |
| Ring size | `BEACON_KEY_COUNT` (96 by default = 24 h at 15 min) |
| Period | `BEACON_ROTATE_SECONDS` (900 s; override with `-D` for testing) |
| Start slot | random at boot, so a reboot doesn't always reveal slot 0 |
| Address | re-derived per key, so it rotates with it |

Design detail: the device and the fetcher never need a synchronised clock,
because the fetcher asks Apple for **every** hash in the ring. The device just walks the ring; whichever slot was active when an iPhone
saw it will have a report under that slot's hash.

Rotation stops advertising, reprograms the random address, sets the new payload
and restarts — `ble_gap_adv_stop()` does not emit `BLE_GAP_EVENT_ADV_COMPLETE`
on this NimBLE port, so the restart is driven from the main loop rather than an
event callback.

`scripts/keygen.py` reuses the existing `keys/beacon.priv.hex` as slot 0, so
reports filed before the upgrade stay in the searched hash set.

### Radio supervision

Two timers and one escalation keep the tag on air:

| Guard | Period | What it does |
| --- | --- | --- |
| Key rotation | 900 s | stop → 250 ms → start with the new address and payload |
| Re-arm | 300 s | stop → 250 ms → start again on the *same* key |
| Escalation | 5 failures | reboot the MCU |

The periodic re-arm exists because the controller can stop transmitting while
the host still believes the advertiser is running. That happened in the field: a
tag with a healthy serial log — clean rotation, stable heap, no errors — was
invisible on air for hours, and only a reset brought it back. Since the host
cannot observe its own transmissions, the only defence is to re-arm blindly.

If a restart fails five times in a row (~25 s), the firmware reboots. The key
ring lives in flash and the start slot is random, so a reboot is harmless.

Boot diagnostics live in NVS and print at every start: `boot #`, `reset reason`
and `watchdog restarts`. A tag that browned out or rebooted while out of reach
therefore reports it the next time it is plugged in.

### Multiple tags

Every tag needs its **own ring**. Never share one: both devices would advertise
the same keys, so Apple's reports under a given hash would mix both devices'
sightings and their locations would be indistinguishable.

```bash
python scripts/keygen.py --name tag2 --no-header    # -> keys/tag2_keys.json
```

`--no-header` skips the firmware header (use `--header src/tag2_keys.h` when you
want one to flash). The watcher picks up every `keys/<name>_keys.json` and
exposes each as its own tag — no restart of the beacon side needed.

#### Automatic on flash

`platformio.ini` runs `scripts/prebuild_keys.py` before every build, so you
never call keygen by hand:

```powershell
pio run -t upload                        # tag "beacon"
$env:BEACON_TAG="tag2"; pio run -t upload   # tag "tag2"
```

The hook:

- creates `keys/<tag>_keys.json` **once** (using any Python on PATH that has
  `cryptography`, since PlatformIO's own Python doesn't ship it)
- re-renders `src/beacon_keys.h` only when the ring actually changed
- is idempotent: re-flashing the same tag never rotates its identity

`BEACON_PYTHON` overrides which interpreter is used for generation; setting
`custom_tag` in `platformio.ini` does the same as the env var.

### Why NimBLE, not `BLEDevice`

PlatformIO `espressif32` resolves to platform 6.9.0 with **Arduino core 3.0.0**,
which removed the Bluedroid `BLE` library. The prebuilt libs ship **NimBLE**
(`CONFIG_BT_NIMBLE_ENABLED=1`), so the firmware talks to the NimBLE host API
directly — which also gives byte-exact control.

Frame reference: [OpenHaystack](https://github.com/seemoo-lab/openhaystack)
`Firmware/ESP32/main/openhaystack_main.c`.

## Retrieving reports (Apple account side)

The beacon needs nothing from Apple. Reading the reports does: they live on
Apple's servers, filed under `SHA-256(advertising key)`, and Apple only serves
them to an authenticated account. This is **not** the Find My app and the
accessory never appears there — that requires an MFi certificate only Apple
issues to manufacturers.

### Why a macOS Anisette backend

Apple binds authentication to the platform that minted the Anisette (ADI)
machine identity (changed ~12 Oct 2026):

| ADI platform | Result |
| --- | --- |
| Android (every classic Docker anisette) | `-80045` "This action cannot be completed at this time." |
| Windows + Mac identity | `-80044` / HTTP 403 |
| Windows + AuthKitWin identity | login works, but tokens contain **only** `mmeAuthToken` |
| **macOS** (this setup) | login works **and** yields `searchPartyToken` |

`searchPartyToken` is what report fetching needs, so **macOS is the only usable
backend**. `ghcr.io/fdkevin0/anisette-server-rs --backend macos` runs Apple's
macOS ADI under an emulator, so no Mac is required.

### Patched endpoint

`christld/macless-haystack` (March 2026) predates the Oct-2026 changes. The
patched file is `scripts/haystack/patched/pypush_gsa_icloud.py`, built into
`bt-beacon-haystack` by `scripts/haystack/Dockerfile`. It:

1. Reads the client identity from the Anisette server's `/v3/client_info`
   instead of hardcoding a mismatched one (fixes the HTML 503).
2. Sends the full Anisette header set as the `cpd`, so `X-Apple-I-MD-RINFO`
   matches the provisioned identity.
3. Does 2FA the way AltSign does — `GET /auth/verify/trusteddevice` then
   `GET /grandslam/GsService2/validate` with a `security-code` header. The old
   idmsa path needs an idmsa signin session the SRP flow never returns.
4. Calls `loginDelegates` with the matching platform prefix, the AOSKit service
   suffix and the device/Anisette headers.

The base image's `updateRepo` is skipped because it cannot advance past its
March commit and would fight the patched file.

### Running it

```powershell
# 1. docker + network + anisette(macos) + patched image
wsl -d Ubuntu -u root -- bash scripts/haystack/docker_up.sh

# 2. first login in YOUR terminal (Apple ID, password, trusted-device code)
wsl -d Ubuntu -u root -- docker run --rm -it --name macless-haystack `
    -p 6176:6176 --volume mh_data:/app/endpoint/data --network mh-network bt-beacon-haystack

# 3. after "serving at port 6176 over HTTP": Ctrl+C, then run detached
wsl -d Ubuntu -u root -- docker run -d --restart unless-stopped --name macless-haystack `
    -p 6176:6176 --volume mh_data:/app/endpoint/data --network mh-network bt-beacon-haystack
```

Credentials are never stored by the tooling as plain text in the repo; the
resulting session lives in `auth.json` inside the `mh_data` volume.

### Hosting on a VPS

`scripts/haystack/vps/docker-compose.yml` runs Anisette + endpoint + dashboard +
Caddy. Ports 6176 and 6969 are **not** published, so the raw endpoint is never
reachable from outside the compose network.

Full guide: [`scripts/haystack/vps/README.md`](scripts/haystack/vps/README.md).
`scripts/haystack/vps/deploy.sh` does a sparse checkout of only the watcher
paths, then `docker compose up -d --build` (only changed services restart).

```bash
cd scripts/haystack/vps
# put your hostname and a password hash in Caddyfile first:
#   docker run --rm caddy:2-alpine caddy hash-password --plaintext 'secret'
docker compose up -d --build
docker compose run --rm endpoint      # one-time Apple ID + trusted-device code
```

Then open `https://<your-host>/` (or `http://<vps>:8099` without TLS) on the
phone or PC: the map, the history timeline, and an **Open latest in Google Maps**
button. That link (`https://www.google.com/maps/search/?api=1&query=lat,lon`) is
handed to the Google Maps app on iOS when installed, and to the browser on a
desktop. There are also Apple Maps and copy-coordinates links.

Ports: the dashboard publishes `${DASHBOARD_PORT:-8099}`. The optional Caddy
front end (profile `tls`) publishes `${HTTP_PORT:-8081}` / `${HTTPS_PORT:-8443}`,
so nothing collides with services already using 80, 443, 8080 or 9000.

Security notes:

- Set `DASHBOARD_USER` / `DASHBOARD_PASS` in `.env` — the dashboard enforces HTTP
  basic auth itself, so publishing 8099 directly is acceptable.
- No domain? Skip the `tls` profile and reach `http://<vps>:8099` over
  **Tailscale**/WireGuard: no public exposure, no certificates.
- The VPS holds the private key and the Apple session (`mh-data` volume). Back
  the volume up; treat the host as sensitive.
- If Apple invalidates `auth.json`, delete it from the volume and re-run the
  interactive step.

### Try the VPS layout locally

`scripts/haystack/vps/docker-compose.local.yml` runs the same three services on
the desktop and reuses the existing volumes, so `auth.json` is picked up and no
new 2FA is needed:

```bash
cd scripts/haystack/vps
docker compose -f docker-compose.local.yml up -d --build
# open http://localhost:8099
docker compose -f docker-compose.local.yml down
```

Startup order is not guaranteed — the endpoint retries Anisette every 10 s, so
the first query can fail for a few seconds.

### Query and decrypt

```powershell
# reports come back as {"results":[...], "statusCode":"200"}
curl.exe -s -X POST http://localhost:6176/ -H "Content-Type: application/json" `
  -d '{\"ids\":[\"GIOJzb43L/bzN4TS3JajukT3tLlKDUTgty0tcTmBh70=\"],\"days\":7}' -o reports.json

python scripts\decrypt_reports.py reports.json
```

```
5 report(s), statusCode=200

1: 2026-11-13T12:57:17+00:00  lat=51.500700 lon=-0.124600 acc=120 status=0 conf=2
```

The hash in `ids` is `base64(sha256(advertising key))`; `scripts/haystack_devices.py`
prints it for the current key, along with a `keys/beacon_devices.json` for
macless-haystack's web/Android frontend. `map_server.py` builds that list for all
96 ring slots and queries them **one id per request** — Apple currently answers
only the tail of a multi-id call — so rotation stays transparent.

### See it on a map

`scripts/map_server.py` serves a Leaflet map, a JSON API and an installable web
app on port 8099. It fetches, decrypts and serves only coordinates — the private
key never leaves that process.

The map has a **timeline scrubber** along the bottom (full width on phones, to the
right of the history panel on desktop). Dragging it moves a red ring to the last
report at or before that moment and highlights the matching history row, so a day
can be replayed either by hand or with the play button.

```powershell
# PC only
python scripts\map_server.py

# phone + PC on the LAN, basic auth on
python scripts\map_server.py --auth argus:secret

# or with the public proxy (no Docker needed)
python scripts\map_server.py --proxy https://haystack-proxy.iokzxt.workers.dev/fetch
```

Open `http://localhost:8099` on the PC. The script also prints a
`http://192.168.x.x:8099` URL for the iPhone (same Wi-Fi); allow the Windows
Firewall prompt the first time. `--host 127.0.0.1` keeps it off the LAN.

The page has an **Open latest in Google Maps** button, an Apple Maps link, a
copy-coordinates link and a **History** list. Both panels fold: the top HUD
keeps only the count and last-seen (everything from the button down is behind the
chevron), and the history list starts folded on phones. Both remember your
choice.

The history list has a **calendar picker**: days with points are highlighted and
clickable, days without data are greyed out, and picking one filters both the map
and the list to that date.

### Add it to the iPhone home screen

There is an **Add to Home Screen** link in the panel. iOS does not let a web page
add itself, so it shows the exact steps (Share → Add to Home Screen); on
Android/Chrome it triggers the native install prompt. The page ships a
`manifest.webmanifest` and a generated 180×180 `apple-touch-icon.png`, so the
icon opens standalone and fetches the latest fix on launch.

### How long history is kept

Two different things:

| Layer | Retention |
| --- | --- |
| Apple's servers | ~7 days. The endpoint can only ask for that window. |
| This project | `--keep-days` (default 365), 0 = forever |

The dashboard merges every point it sees into a history JSON, so Apple's window
only limits how far *back* a fetch reaches — anything already collected stays.
A background poll runs every 15 minutes (`--poll`), so points keep accumulating
even when nobody has the page open.

Size: one point is ~160 bytes. At the default 15-minute poll that is
~96 points/day → ~15 KB/day → ~5.5 MB/year. Two bounds keep it from growing
without limit:

| Option | Default | Effect |
| --- | --- | --- |
| `--keep-days` | 365 | drops points older than N days on every merge |
| `--max-points` | 20000 | hard cap (~3 MB), oldest dropped first |

Set either to `0` to disable that bound. The file is not rotated or split — it is
simply trimmed in place, which keeps the code and the API simple.

#### Keeping more than a year

Raise both bounds, e.g. five years:

```bash
python scripts/map_server.py --keep-days 1825 --max-points 300000
```

Numbers: ~96 points/day × 160 B ≈ **5.5 MB/year**, so 5 years ≈ 28 MB, and
`--max-points 300000` ≈ 48 MB. Two things make that workable:

- **The UI no longer downloads everything.** `/api/summary?tz=…` returns only
  per-day counts for the calendar, and `/api/reports` returns just the selected
  window (`?days=N` or `?from=…&to=…`). Previously every refresh shipped the
  whole file to the browser.
- **Fetches are throttled** by `--refresh-seconds` (default 120), so opening the
  page in several tabs does not hammer Apple.

The default window is `--ui-days 7`; the calendar still shows every day that
exists in the file.

The store is **SQLite** (`PRAGMA journal_mode=WAL`), so inserts are indexed
point-lookups and the windowed queries the API needs (`ts >= ?`, group by day)
never scan a file. A decade of history stays cheap; no rewriting the whole
dataset on each poll.

Migrating from the old JSON store is automatic: on first start, if
`history.json` sits next to the DB, its points are imported and the file is
renamed to `history.json.imported`.

What it does **not** do: recover points from before you started collecting. If
the stack is stopped for more than ~7 days, that gap is gone.

Files: `keys/beacon_history.db` for a native run, the `history` volume
(`/data/history.db`) under compose. The legacy `history.json` is imported once
and renamed.

Alternatives:

- **macless-haystack frontend** (`dchristl.github.io/macless-haystack` or the
  Android app): import `keys/beacon_devices.json` and set the endpoint URL. The
  hosted UI is HTTPS, so an iPhone cannot call a plain-HTTP endpoint — you need
  to host the UI locally or put the endpoint behind TLS.
- **KML export**: reports can be converted for Google My Maps / Google Earth,
  which works on the iPhone anywhere, but only as a static snapshot.


## Files

| File | Purpose |
| --- | --- |
| `src/main.cpp` | NimBLE beacon: frame, random address, non-connectable advertising |
| `src/beacon_keys.h` | 96 advertising keys, one per rotation slot (generated) |
| `keys/beacon_keys.json` | **Secret** — private + advertising key per slot; gitignored |
| `scripts/keygen.py` | Generates the key ring → `keys/` + header |
| `scripts/prebuild_keys.py` | PlatformIO hook: ensure ring + render header |
| `scripts/haystack_devices.py` | `devices.json` + hashed key for the frontend |
| `scripts/decrypt_reports.py` | Decrypt a report JSON into coordinates |
| `scripts/ble_scan.py` | Decode Apple advertisements over the air |
| `scripts/map_server.py` | Leaflet map + windowed JSON API (PC + iPhone on LAN) |
| `scripts/web/index.html` | map UI (static, editable without rebuild) |
| `scripts/web/admin.html` | admin page for users and tag grants |
| `scripts/haystack/docker_up.sh` | dockerd + network + Anisette + image |
| `scripts/haystack/Dockerfile` | Patched endpoint image |
| `scripts/haystack/patched/` | Patched `pypush_gsa_icloud.py` |
| `keys/beacon.priv.hex` | **Secret** — decrypts reports; gitignored |

## Users and the admin page

The dashboard authenticates with **HTTP basic auth** against users stored in
SQLite, and each user only sees the tags granted to them.

| Concept | Behaviour |
| --- | --- |
| Bootstrap admin | `--auth user:pass` (compose reads `DASHBOARD_USER` / `DASHBOARD_PASS`) |
| Admin page | `/admin` — create users, toggle admin, grant tags per user |
| Non-admin | `403` on `/admin`; `/api/tags` and reports only list granted tags |
| No users at all | dashboard is open (local development) |

The Apple session stays **shared**: one account fetches reports for every tag,
because Apple serves any authenticated client the reports for any hash. Users
are an authorisation layer, not separate Apple logins.

## Caveats

- **Key rotation, not perfect privacy.** The ring rotates every 15 minutes, so a
  passive sniffer cannot follow one stable identifier. But the ring is finite
  (96 slots ≈ 24 h), so a patient observer who records for a day can notice the
  repeat. Increase `--count` for a longer cycle.
- **Anti-stalking.** iPhones will eventually warn their owner about an unknown
  tracker travelling with them. That is Apple's protection working — DIY
  beacons have no speaker to chirp.
- **Your own property only.** Tracking a person without consent is illegal.
- **Unofficial.** Apple's backend is undocumented and changed twice in Oct 2026
  alone. This setup can break at any time.
- **Power.** One BLE advertisement every 1–2 s draws ~10–15 mA from a 3S pack,
  so a 1000 mAh battery lasts days, not hours. Light-sleep between bursts is the
  next optimisation.
- **Apple truncates multi-id fetches that carry a `startDate`.** Since mid-Nov
  2026 a request containing `startDate: 1` returns reports for the *last* id in
  the list and silently ignores the rest — a 192-hash sweep returned one slot's
  data and nothing else, so both tags looked dead while `last_ok` stayed green.
  Removing the date field restores normal answers, so
  `scripts/haystack/patch_endpoint.py` strips it at image build time and one
  request carries the whole ring again. `--fetch-chunk` (default 192) plus an
  automatic one-id-per-request fallback guard against a regression.
- **Apple session expiry.** The stored session lasts weeks to months, then needs
  a fresh login (`bash deploy.sh login` on the VPS). The dashboard shows a
  banner when fetching starts failing; history already collected is unaffected.
- **Privacy of the key.** Anyone holding `keys/beacon.priv.hex` can decrypt every
  report ever filed for this beacon. Treat it like an SSH private key. It is
  gitignored and deliberately **not** in the repository — back it up somewhere
  safe, because without it the stored history is unreadable.

## Tooling notes

- `.venv/` holds `bleak` for `scripts/ble_scan.py` and `pyserial` for
  `scripts/serial_log.py`. Recreate with
  `python -m venv .venv; .\.venv\Scripts\pip install bleak pyserial`. The
  PowerShell WinRT watcher starts but delivers no events on this machine.
- `scripts/serial_log.py` timestamps every serial line and writes a marker after
  90 s of silence, so a tag that dies overnight leaves evidence: heartbeats
  stopping means a hang, a boot banner means a reset.
- Two PlatformIO cores are installed: `pio` on `PATH` is a stale 6.1.19 pip
  install that crashes on Unicode output; use
  `%USERPROFILE%\.platformio\penv\Scripts\pio.exe` (6.2.0).
- The `SHA-256 comparison failed ... Expected: ffff...` line after reset is
  normal on a chip with no secure-boot digest burned.
- Windows caches identical BLE advertisements, so `ble_scan.py` may miss a
  beacon whose payload has not changed recently. The firmware's 30 s
  `beaconing` log line is the ground truth.
