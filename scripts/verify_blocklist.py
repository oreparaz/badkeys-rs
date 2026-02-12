#!/usr/bin/env python3
"""Verify the generated P256 blocklist database.

Checks file integrity: size, sort order, category distribution.

Usage:
    python3 verify_blocklist.py data/p256_blocklist.bin
"""

import struct
import sys
from collections import Counter
from pathlib import Path

RECORD_SIZE = 16
HASH_SIZE = 15

CATEGORY_NAMES = {
    0: "debianssl",
    1: "rfc",
    2: "documentation",
    3: "firmware",
    4: "localhostcert",
    5: "softwaretests",
    6: "testvectors",
    7: "misc",
    8: "gitkeys",
    9: "fwkeys",
    10: "pkgkeys",
    11: "webkeys",
    12: "malware",
}


def main():
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <blocklist.bin>")
        sys.exit(1)

    path = Path(sys.argv[1])
    data = path.read_bytes()

    # Check size
    if len(data) % RECORD_SIZE != 0:
        print(f"FAIL: file size {len(data)} is not a multiple of {RECORD_SIZE}")
        sys.exit(1)

    num_records = len(data) // RECORD_SIZE
    print(f"File: {path}")
    print(f"Size: {len(data)} bytes")
    print(f"Records: {num_records}")

    # Check sort order and collect stats
    category_counts = Counter()
    prev_hash = b"\x00" * HASH_SIZE
    first = True
    for i in range(num_records):
        offset = i * RECORD_SIZE
        h = data[offset : offset + HASH_SIZE]
        cat_id = data[offset + HASH_SIZE]

        if not first and h <= prev_hash:
            print(f"FAIL: records not sorted at index {i}")
            print(f"  prev: {prev_hash.hex()}")
            print(f"  curr: {h.hex()}")
            sys.exit(1)

        if h == prev_hash and first is False:
            print(f"FAIL: duplicate hash at index {i}: {h.hex()}")
            sys.exit(1)

        category_counts[cat_id] += 1
        prev_hash = h
        first = False

    print(f"\nSort order: OK")
    print(f"No duplicates: OK")

    print(f"\nCategory distribution:")
    for cat_id in sorted(category_counts):
        name = CATEGORY_NAMES.get(cat_id, f"unknown({cat_id})")
        count = category_counts[cat_id]
        print(f"  [{cat_id:2d}] {name:20s}: {count:>8d}")

    print(f"\nTotal: {num_records}")
    print("PASS")


if __name__ == "__main__":
    main()
