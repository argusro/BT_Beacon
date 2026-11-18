#!/usr/bin/env python3
"""Remove the bogus ``startDate: 1`` from the upstream endpoint's Apple request.

Apple answers only the *tail* of a multi-id fetch when ``startDate`` is present
(verified 2026-11-17/18: two ids returned reports for the last one; the same two
ids with no date fields returned both). The endpoint filters the response
locally by ``days`` anyway, so the date in the request was never useful.

Runs as a Docker build step. If upstream has already changed the line, the build
still succeeds with a warning; only an ambiguous match (more than one) fails.
"""

import pathlib
import re
import sys

PATH = pathlib.Path("/app/endpoint/mh_endpoint.py")

PATTERN = re.compile(
    r'\{\s*"startDate"\s*:\s*1\s*,\s*"ids"\s*:\s*list\(\s*body\[\s*[\'"]ids[\'"]\s*\]\s*\)\s*\}'
)


def main() -> int:
    source = PATH.read_text()
    patched, count = PATTERN.subn('{"ids": list(body["ids"])}', source)
    if count == 0:
        print(f"endpoint: no startDate block found in {PATH}; leaving it untouched")
        return 0
    if count > 1:
        print(f"!! {count} startDate blocks found in {PATH}; refusing to guess",
              file=sys.stderr)
        return 1
    PATH.write_text(patched)
    print(f"endpoint patched: removed startDate from {PATH}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
