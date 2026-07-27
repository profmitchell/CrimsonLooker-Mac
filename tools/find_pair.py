#!/usr/bin/env python3
"""Filter the dylib's scan output down to the likely range/pull pair.

The scan logs every 20.0/40.0 pair it finds in __DATA, which is usually dozens
of lines. The real pair is the one spaced like the Windows build's, so ranking by
distance from the known-good delta gets you there immediately.

Usage:
    tools/find_pair.py ~/Library/Application\\ Support/CDUMM/runtime/CrimsonLooker.log
"""
from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

# Spacing between the range and pull floats. 0xB40 on the Windows build, 0xB80 on
# the first mapped Mac build. Expect small drift, not a different magnitude.
EXPECTED_DELTA = 0xB80

LINE = re.compile(
    r"scan: pair range=0x(?P<range>[0-9a-f]+) "
    r"pull=0x(?P<pull>[0-9a-f]+) "
    r"delta=0x(?P<delta>[0-9a-f]+)"
)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("log", type=Path, help="CrimsonLooker.log to read")
    parser.add_argument(
        "--top", type=int, default=10, help="how many candidates to show (default 10)"
    )
    args = parser.parse_args()

    if not args.log.is_file():
        print(f"no such log: {args.log}", file=sys.stderr)
        return 1

    text = args.log.read_text(encoding="utf-8", errors="replace")
    pairs = {
        (m.group("range"), m.group("pull"), int(m.group("delta"), 16))
        for m in LINE.finditer(text)
    }
    if not pairs:
        print(
            "no 'scan: pair' lines found. launch the game with the dylib injected "
            "and play for about a minute, then try again.",
            file=sys.stderr,
        )
        return 1

    ranked = sorted(pairs, key=lambda p: abs(p[2] - EXPECTED_DELTA))

    print(f"{len(pairs)} pair(s) found. Closest to the expected 0x{EXPECTED_DELTA:x} spacing:\n")
    for range_addr, pull_addr, delta in ranked[: args.top]:
        drift = delta - EXPECTED_DELTA
        print(
            f"  range=0x{range_addr}  pull=0x{pull_addr}  "
            f"delta=0x{delta:x}  drift={drift:+#x}"
        )

    # Adjacent floats routinely tie on spacing, so there is usually more than one
    # equally good answer. Saying so is more useful than picking arbitrarily.
    best_drift = abs(ranked[0][2] - EXPECTED_DELTA)
    tied = [p for p in ranked if abs(p[2] - EXPECTED_DELTA) == best_drift]

    print(f"\n{'Candidates' if len(tied) > 1 else 'Most likely'} at drift {best_drift:+#x}:")
    for range_addr, pull_addr, _delta in tied:
        print(f"  kKnownRangeUnslid = 0x{range_addr}ull")
        print(f"  kKnownPullUnslid  = 0x{pull_addr}ull")
    if len(tied) > 1:
        print(
            "\nThese are indistinguishable by spacing alone. Write to each range "
            "address in turn and keep the one whose logged old value is exactly 20 "
            "and which actually changes reach in game."
        )
    else:
        print(
            "\nConfirm before trusting it: write to the range address and check the "
            "logged old value is exactly 20."
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
