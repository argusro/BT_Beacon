"""
PlatformIO pre-build hook: make sure the tag has a key ring and that
src/beacon_keys.h matches it.

- The ring is created **once** per tag (``keys/<name>_keys.json``) and reused on
  every later flash, so re-flashing never changes the tag's identity.
- Rendering the header is pure stdlib, so it works with PlatformIO's own Python.
- Creating a new ring needs ``cryptography``; if the PIO Python lacks it we look
  for another interpreter on PATH (override with BEACON_PYTHON).

Pick the tag per device:

    $env:BEACON_TAG="tag2"; pio run -t upload        # PowerShell
    BEACON_TAG=tag2 pio run -t upload                # bash

or set ``custom_tag = tag2`` in the environment section of platformio.ini.
"""

Import("env")

import os
import pathlib
import shutil
import subprocess
import sys

ROOT = pathlib.Path(env.subst("$PROJECT_DIR"))
HEADER_REL = "src/beacon_keys.h"

TAG = (os.environ.get("BEACON_TAG")
       or env.GetProjectOption("custom_tag", None)
       or "beacon")
STORE = ROOT / "keys" / f"{TAG}_keys.json"
KEYGEN = ROOT / "scripts" / "keygen.py"


def crypto_python():
    """First interpreter on PATH that can import cryptography."""
    candidates = [os.environ.get("BEACON_PYTHON"), "python", "python3", "py"]
    for name in candidates:
        if not name:
            continue
        exe = shutil.which(name)
        if not exe:
            continue
        try:
            probe = subprocess.run([exe, "-c", "import cryptography"],
                                   capture_output=True, timeout=30)
        except (OSError, subprocess.SubprocessError):
            continue
        if probe.returncode == 0:
            return exe
    return None


def ensure_keys():
    if not KEYGEN.exists():
        print(f"[keys] !! {KEYGEN} missing, skipping key setup")
        return

    if STORE.exists():
        # Idempotent: only re-renders the header if the ring changed.
        subprocess.check_call([sys.executable, str(KEYGEN), "--name", TAG,
                               "--header", HEADER_REL, "--if-missing"])
        return

    py = crypto_python()
    if not py:
        print(f"[keys] !! no ring for tag '{TAG}' and no Python with cryptography found.")
        print(f"[keys]    run: python scripts/keygen.py --name {TAG}")
        return

    print(f"[keys] creating a new ring for tag '{TAG}' ({py})")
    subprocess.check_call([py, str(KEYGEN), "--name", TAG, "--header", HEADER_REL])


ensure_keys()
