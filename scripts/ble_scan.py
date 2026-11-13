#!/usr/bin/env python3
"""
Scan for BLE advertisements and decode Apple Find My (Offline Finding) frames.

Usage:
    python scripts/ble_scan.py [seconds]

Uses a detection callback rather than a one-shot discovery because Windows
drops devices from single-shot scans. Apple (company ID 0x004C) advertisements
are decoded; Find My type 0x12 frames get their split key reassembled.
"""

import asyncio
import sys
import time

from bleak import BleakScanner

APPLE_COMPANY_ID = 0x004C


def describe(payload: bytes) -> str:
    if not payload:
        return "empty"

    kind = payload[0]

    # Find My "Nearby Info": 0x12, len, status, ...
    if kind == 0x12 and len(payload) >= 4:
        length = payload[1]
        status = payload[2]
        body = payload[3:]
        if length == 0x19 and len(body) >= 24:
            key_tail = body[:22]
            bits = body[22]
            hint = body[23]
            return (
                f"FIND MY / Offline Finding\n"
                f"      status=0x{status:02x}  key[6..27]={key_tail.hex()}\n"
                f"      key[0]>>6=0x{bits:02x}  hint=0x{hint:02x}"
            )
        return f"Find My Nearby Info (short form, status=0x{status:02x}, len={length})"

    if kind == 0x10:
        return f"Nearby Info (len={len(payload)})"
    if kind == 0x01:
        return f"AirDrop (len={len(payload)})"
    if kind == 0x07:
        return f"AirPods (len={len(payload)})"

    return f"Apple type 0x{kind:02x} (len={len(payload)})"


async def main() -> int:
    duration = float(sys.argv[1]) if len(sys.argv) > 1 else 10.0
    seen: dict[str, dict] = {}

    def on_detect(device, adv) -> None:
        entry = seen.setdefault(
            device.address,
            {"rssi": adv.rssi, "count": 0, "adv": adv},
        )
        entry["count"] += 1
        entry["rssi"] = adv.rssi

    print(f"scanning {duration:.0f}s ...\n")
    scanner = BleakScanner(detection_callback=on_detect)
    await scanner.start()
    await asyncio.sleep(duration)
    await scanner.stop()

    apple = {a: e for a, e in seen.items() if APPLE_COMPANY_ID in e["adv"].manufacturer_data}
    if not apple:
        print("no Apple advertisements seen "
              f"({len(seen)} BLE devices total)")
        return 1

    for address, entry in sorted(apple.items(), key=lambda kv: -kv[1]["rssi"]):
        payload = entry["adv"].manufacturer_data[APPLE_COMPANY_ID]
        print(f"{address}  rssi={entry['rssi']:>4} dBm  seen={entry['count']}x")
        print(f"  manufacturer data: {payload.hex(' ')}")
        print(f"  -> {describe(payload)}")
        print()

    print(f"({len(seen)} BLE devices seen in total)")
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
