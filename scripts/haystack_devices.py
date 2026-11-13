#!/usr/bin/env python3
"""
Emit a macless-haystack devices.json for the beacon's key ring.

The frontend stores one private key plus a list of `additionalKeys` and queries
all of their hashes, which is exactly what key rotation needs.

Usage:
    python scripts/haystack_devices.py [name]
"""

import base64
import json
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent


def main() -> int:
    name = sys.argv[1] if len(sys.argv) > 1 else "beacon"

    json_path = ROOT / "keys" / f"{name}_keys.json"
    if json_path.exists():
        ring = json.loads(json_path.read_text())["keys"]
        privs = [bytes.fromhex(entry["priv"]) for entry in ring]
        advs = [bytes.fromhex(entry["adv"]) for entry in ring]
    else:
        privs = [bytes.fromhex((ROOT / "keys" / f"{name}.priv.hex").read_text().strip())]
        advs = [bytes.fromhex((ROOT / "keys" / f"{name}.pub.hex").read_text().strip())]

    import hashlib

    priv_b64 = [base64.b64encode(p).decode() for p in privs]
    adv_b64 = base64.b64encode(advs[0]).decode()
    s256_b64 = base64.b64encode(hashlib.sha256(advs[0]).digest()).decode()

    # Schema from macless-haystack generate_keys.py: one primary key plus extras.
    devices = [{
        "id": 1,
        "colorComponents": [0, 1, 0, 1],
        "name": name,
        "privateKey": priv_b64[0],
        "icon": "",
        "isActive": True,
        "additionalKeys": priv_b64[1:],
    }]

    out = ROOT / "keys" / f"{name}_devices.json"
    out.write_text(json.dumps(devices, indent=2) + "\n")

    print(f"key slots    : {len(privs)}")
    print(f"slot 0 adv   : {adv_b64}")
    print(f"slot 0 hash  : {s256_b64}")
    print(f"wrote {out.relative_to(ROOT)}")
    print()
    print("Contains private keys - import into the frontend, never commit.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
