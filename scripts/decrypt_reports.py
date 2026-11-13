#!/usr/bin/env python3
"""
Decrypt Apple Find My location reports for the beacon's key ring.

Usage:
    python scripts/decrypt_reports.py <reports.json> [name]

<reports.json> is the endpoint's response, e.g.
    {"results": [{"payload": "<base64>", "id": "<hash>"}], "statusCode": "200"}

Each report is matched to its key slot by the `id` (hash) field, so a rotating
key ring works transparently.

Report payload layout (two variants in the wild):

    len 88:  ts(4) | conf(1) | eph_point(57) | ct(10) | tag(16)
    len 89:  ts(4) | pad(1)  | conf(1)      | eph_point(57) | ct(10) | tag(16)

Key derivation is a single-pass X9.63-style KDF over the ECDH secret and the
ephemeral point, then AES-128-GCM. Reference: malmeloo/FindMy.py
findmy/reports/reports.py (the newer MacOS 14+ report format).
"""

import base64
import hashlib
import json
import pathlib
import struct
import sys
from datetime import datetime, timedelta, timezone

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

ROOT = pathlib.Path(__file__).resolve().parent.parent
APPLE_EPOCH = datetime(2001, 1, 1, tzinfo=timezone.utc)
CURVE = ec.SECP224R1()


def hash_of_adv(adv: bytes) -> str:
    return base64.b64encode(hashlib.sha256(adv).digest()).decode()


def load_keys(name: str = "beacon", keys_file: str | None = None) -> dict:
    """Return {hash_b64: private_key} for every slot in the rotation ring."""
    json_path = pathlib.Path(keys_file) if keys_file else ROOT / "keys" / f"{name}_keys.json"

    if json_path.exists() and json_path.suffix == ".json":
        data = json.loads(json_path.read_text())
        keys = {}
        for entry in data["keys"]:
            key = ec.derive_private_key(int(entry["priv"], 16), CURVE)
            keys[entry.get("hash_b64") or hash_of_adv(bytes.fromhex(entry["adv"]))] = key
        return keys

    # legacy single-key layout
    priv_path = pathlib.Path(keys_file) if keys_file else ROOT / "keys" / f"{name}.priv.hex"
    key = ec.derive_private_key(
        int.from_bytes(bytes.fromhex(priv_path.read_text().strip()), "big"), CURVE
    )
    adv = key.public_key().public_numbers().x.to_bytes(28, "big")
    return {hash_of_adv(adv): key}


def decrypt_payload(payload_b64: str, private_key) -> dict:
    payload = base64.b64decode(payload_b64)
    encrypted = payload[4:]
    if len(encrypted) == 85:  # 89-byte variant: one padding byte before the key
        encrypted = encrypted[1:]

    point = encrypted[1:58]
    eph = ec.EllipticCurvePublicKey.from_encoded_point(CURVE, point)
    shared = private_key.exchange(ec.ECDH(), eph)
    symmetric_key = hashlib.sha256(shared + b"\x00\x00\x00\x01" + point).digest()

    ciphertext = encrypted[58:68]
    tag = encrypted[68:]
    plaintext = AESGCM(symmetric_key[:16]).decrypt(
        symmetric_key[16:], ciphertext + tag, None
    )

    lat, lon, accuracy, status = struct.unpack(">iiBB", plaintext[:10])
    timestamp = struct.unpack(">I", payload[:4])[0]
    confidence = payload[5] if len(payload) != 88 else payload[4]

    return {
        "when": (APPLE_EPOCH + timedelta(seconds=timestamp)).isoformat(),
        "lat": lat / 1e7,
        "lon": lon / 1e7,
        "accuracy": accuracy,
        "status": status,
        "confidence": confidence,
    }


def decrypt_report(report: dict, keys: dict) -> dict | None:
    """Decrypt one report, preferring the key slot named by its hash."""
    matched = keys.get(report.get("id"))
    candidates = [matched] if matched is not None else list(keys.values())
    for candidate in candidates:
        try:
            return decrypt_payload(report["payload"], candidate)
        except Exception:  # noqa: BLE001
            continue
    return None


def main() -> int:
    if len(sys.argv) < 2:
        print(__doc__)
        return 2

    reports_path = pathlib.Path(sys.argv[1])
    name = sys.argv[2] if len(sys.argv) > 2 else "beacon"
    keys = load_keys(name)

    data = json.loads(reports_path.read_text())
    results = data.get("results", [])
    print(f"{len(results)} report(s), statusCode={data.get('statusCode')}, "
          f"{len(keys)} key slot(s)\n")

    for i, report in enumerate(results, start=1):
        info = decrypt_report(report, keys)
        if info is None:
            print(f"{i}: could not decrypt")
            continue
        print(f"{i}: {info['when']}  lat={info['lat']:.6f} lon={info['lon']:.6f} "
              f"acc={info['accuracy']} status={info['status']} conf={info['confidence']}")
        print(f"    https://www.openstreetmap.org/?mlat={info['lat']}&mlon={info['lon']}"
              f"#map=17/{info['lat']}/{info['lon']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
