#!/usr/bin/env python3
"""Record a tag's serial output to a file, with timestamps and gap markers.

The point is to catch a silent failure after the fact: leave this running while
the tag is on its real power source, then look at the last lines before the log
goes quiet. If the tag hung, the heartbeat lines just stop. If it browned out or
panicked, you get the boot banner (boot # / reset reason) that follows.

Powering over a data-only USB cable (TX/RX/GND, no VBUS) keeps the log alive
while the tag runs from its battery.

    python scripts/serial_log.py --port COM10 --hours 6 --out tag2.log
"""

from __future__ import annotations

import argparse
import datetime as dt
import sys
import time

import serial

GAP_SECONDS = 90.0
REOPEN_SECONDS = 2.0


def stamp() -> str:
    return dt.datetime.now().astimezone().isoformat(timespec="seconds")


def open_port(port: str, baud: int) -> serial.Serial:
    ser = serial.Serial()
    ser.port = port
    ser.baudrate = baud
    ser.timeout = 0.2
    # Don't poke the reset lines: DTR/RTS toggling reboots the ESP32.
    ser.dtr = False
    ser.rts = False
    ser.open()
    return ser


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--port", default="COM10")
    ap.add_argument("--baud", type=int, default=115200)
    ap.add_argument("--hours", type=float, default=6.0)
    ap.add_argument("--out", default="serial.log")
    ap.add_argument("--gap", type=float, default=GAP_SECONDS,
                    help="seconds of silence before a gap marker is written")
    args = ap.parse_args()

    deadline = time.time() + args.hours * 3600
    ser: serial.Serial | None = None
    last_line = time.time()

    with open(args.out, "w", encoding="utf-8", buffering=1) as fh:
        fh.write(f"# {stamp()}  logging {args.port} @ {args.baud} for {args.hours}h\n")
        while time.time() < deadline:
            if ser is None:
                try:
                    ser = open_port(args.port, args.baud)
                    time.sleep(0.3)
                    ser.reset_input_buffer()
                    fh.write(f"# {stamp()}  port open\n")
                    last_line = time.time()
                except (serial.SerialException, OSError) as exc:
                    fh.write(f"# {stamp()}  cannot open {args.port}: {exc}\n")
                    time.sleep(REOPEN_SECONDS)
                continue

            try:
                raw = ser.readline()
            except (serial.SerialException, OSError) as exc:
                fh.write(f"# {stamp()}  port lost: {exc}\n")
                try:
                    ser.close()
                except Exception:
                    pass
                ser = None
                continue

            now = time.time()
            if raw:
                text = raw.decode("utf-8", "replace").rstrip("\r\n")
                fh.write(f"{stamp()}  {text}\n")
                last_line = now
            elif now - last_line >= args.gap:
                fh.write(f"# {stamp()}  no data for {now - last_line:.0f}s\n")
                last_line = now

    if ser is not None:
        try:
            ser.close()
        except Exception:
            pass
    print(f"wrote {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
