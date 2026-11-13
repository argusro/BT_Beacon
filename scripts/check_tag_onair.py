import asyncio
import json
import pathlib

from bleak import BleakScanner

ROOT = pathlib.Path(r"C:\Users\argus\Documents\Code\BT_Beacon")
ring = json.loads((ROOT / "keys" / "tag2_keys.json").read_text())["keys"]

frames = {}
for i, e in enumerate(ring):
    k = bytes.fromhex(e["adv"])
    # bleak strips the 2-byte company id: payload starts at "12 19"
    f = bytes([0x12, 0x19, 0x00]) + k[6:28] + bytes([k[0] >> 6, 0x00])
    frames[f] = i + 1

print(f"watching for any of {len(frames)} tag2 slots for 50s ...")

seen = {}


async def main():
    def cb(dev, adv):
        md = adv.manufacturer_data.get(0x4C)
        if not md:
            return
        if md in frames:
            seen[(dev.address.upper(), frames[md])] = adv.rssi
        elif md[:2] == b"\x12\x19":
            seen[(dev.address.upper(), "other-OF")] = adv.rssi

    scanner = BleakScanner(detection_callback=cb)
    await scanner.start()
    await asyncio.sleep(50)
    await scanner.stop()


asyncio.run(main())

if seen:
    for (addr, slot), rssi in sorted(seen.items()):
        print(f"  {addr}  slot {slot}  rssi={rssi}")
else:
    print("  no Offline Finding frames seen at all")
