#!/usr/bin/env python3
"""
Watch the air for any of our tags' advertisements.

Every keys/<name>_keys.json is a ring; the script builds the expected
manufacturer payload for every slot and reports which tag/slot it saw.

Usage:
    python scripts/check_tag_onair.py [--seconds 60] [--tag tag2]
"""

import argparse
import asyncio
import json
import pathlib

from bleak import BleakScanner

ROOT = pathlib.Path(__file__).resolve().parent.parent


def load_frames() -> dict[bytes, tuple[str, int]]:
    frames: dict[bytes, tuple[str, int]] = {}
    for path in sorted((ROOT / "keys").glob("*_keys.json")):
        tag = path.name[:-len("_keys.json")]
        for i, entry in enumerate(json.loads(path.read_text())["keys"]):
            k = bytes.fromhex(entry["adv"])
            # bleak hands us the payload *after* the 2-byte company id
            payload = (bytes([0x12, 0x19, 0x00]) + k[6:28]
                       + bytes([k[0] >> 6, 0x00]))
            frames[payload] = (tag, i + 1)
    return frames


async def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--seconds", type=float, default=90)
    parser.add_argument("--tag", default=None)
    args = parser.parse_args()

    frames = load_frames()
    tags = sorted({t for t, _ in frames.values()})
    print(f"watching {len(frames)} keys across {len(tags)} tag(s): {', '.join(tags)}")
    print(f"scanning for {args.seconds:.0f}s ...\n")

    seen: dict[tuple[str, int, str], int] = {}
    others: dict[str, tuple[int, str]] = {}

    def on_detect(device, adv):
        payload = adv.manufacturer_data.get(0x4C)
        if payload is None or payload[:2] != b"\x12\x19":
            return
        if payload in frames:
            tag, slot = frames[payload]
            if args.tag and tag != args.tag:
                return
            seen[(tag, slot, device.address.upper())] = adv.rssi
        else:
            others.setdefault(device.address.upper(), (adv.rssi, payload.hex(" ")))

    scanner = BleakScanner(detection_callback=on_detect)
    await scanner.start()
    await asyncio.sleep(args.seconds)
    await scanner.stop()

    for (tag, slot, addr), rssi in sorted(seen.items()):
        print(f"  OURS  {tag:<10} slot {slot:>3}   {addr}   rssi={rssi:>4} dBm")

    for addr, (rssi, data) in sorted(others.items()):
        print(f"  other {addr}   rssi={rssi:>4} dBm   {data}")

    if not seen:
        print("\nno tag of ours seen (other Offline Finding devices listed above, if any)")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
