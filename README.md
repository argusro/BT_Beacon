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
chip        : ESP32-C3 rev 4
adv key     : 621112aa...22af
BLE address : de 0a 24 e6 00 aa
adv frame   : 1e ff 4c 00 12 19 00 d8 2a 0c 3b 0d 3e 7e 17 b1 f9 8d 34 44 85 f5 d8 d0 cc 10 3b 52 35 00 00
-----------------------------------------
advertising as a Find My accessory
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
96 ring slots and queries them in a single request, so rotation is transparent.

### See it on a map

`scripts/map_server.py` serves a Leaflet map, a JSON API and an installable web
app on port 8099. It fetches, decrypts and serves only coordinates — the private
key never leaves that process.

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
copy-coordinates link and a **History** list. The list is collapsible (starts
folded on phones, remembers your choice) and has a **calendar picker**: days with
points are highlighted and clickable, days without data are greyed out, and
picking one filters both the map and the list to that date.

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

Size: one point is ~160 bytes of JSON. At the default 15-minute poll that is
~96 points/day → ~15 KB/day → ~5.5 MB/year. Two bounds keep it from growing
without limit:

| Option | Default | Effect |
| --- | --- | --- |
| `--keep-days` | 365 | drops points older than N days on every merge |
| `--max-points` | 20000 | hard cap (~3 MB), oldest dropped first |

Set either to `0` to disable that bound. The file is not rotated or split — it is
simply trimmed in place, which keeps the code and the API simple.

What it does **not** do: recover points from before you started collecting. If
the stack is stopped for more than ~7 days, that gap is gone.

Files: `keys/beacon_history.json` for a native run, the `history` volume
(`/data/history.json`) under compose.

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
| `scripts/haystack_devices.py` | `devices.json` + hashed key for the frontend |
| `scripts/decrypt_reports.py` | Decrypt a report JSON into coordinates |
| `scripts/ble_scan.py` | Decode Apple advertisements over the air |
| `scripts/map_server.py` | Leaflet map + decrypted JSON API (PC + iPhone on LAN) |
| `scripts/haystack/docker_up.sh` | dockerd + network + Anisette + image |
| `scripts/haystack/Dockerfile` | Patched endpoint image |
| `scripts/haystack/patched/` | Patched `pypush_gsa_icloud.py` |
| `keys/beacon.priv.hex` | **Secret** — decrypts reports; gitignored |

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
- **Power.** Continuous 1–2 s advertising flattens a small LiPo in a day or two.
  Light-sleep between bursts is the next optimisation.
- **Privacy of the key.** Anyone holding `keys/beacon.priv.hex` can decrypt every
  report ever filed for this beacon. Treat it like an SSH private key. It is
  gitignored and deliberately **not** in the repository — back it up somewhere
  safe, because without it the stored history is unreadable.

## Tooling notes

- `.venv/` holds `bleak` for `scripts/ble_scan.py`. Recreate with
  `python -m venv .venv; .\.venv\Scripts\pip install bleak`. The PowerShell WinRT
  watcher starts but delivers no events on this machine.
- Two PlatformIO cores are installed: `pio` on `PATH` is a stale 6.1.19 pip
  install that crashes on Unicode output; use
  `%USERPROFILE%\.platformio\penv\Scripts\pio.exe` (6.2.0).
- The `SHA-256 comparison failed ... Expected: ffff...` line after reset is
  normal on a chip with no secure-boot digest burned.
- Windows caches identical BLE advertisements, so `ble_scan.py` may miss a
  beacon whose payload has not changed recently. The firmware's 30 s
  `beaconing` log line is the ground truth.
